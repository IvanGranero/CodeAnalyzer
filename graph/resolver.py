import logging
from graph.manager import GraphManager

logger = logging.getLogger(__name__)

class GraphResolver:
    """
    Executes Post-Ingestion graph completion passes.
    Bakes semantic meaning (taint, data flow, dead code) directly into Neo4j.
    """
    
    def __init__(self, graph_manager: GraphManager):
        self.db = graph_manager.db

    def run_all_passes(self):
        """Executes the full suite of resolution passes."""
        logger.info("=== Starting Graph Resolution & Completion Passes ===")
        self._resolve_uds_taint()
        self._flag_dead_code()
        self._resolve_rte_data_flow()
        self._flag_dangerous_sinks()
        logger.info("=== Graph Resolution Complete ===")

    def _resolve_uds_taint(self):
        """
        Dynamically finds DIDs and RIDs, links them to the UDS Attack Surface, 
        and traces the taint down the call stack.
        """
        logger.info("Resolving UDS Attack Surface Entry Points...")
        
        # Step 1: Find functions with _DID_ or _RID_ in their name and wire them up
        map_uds_query = """
        MATCH (f:Function)
        WHERE f.name CONTAINS "_DID_" OR f.name CONTAINS "_RID_"
        
        // Extract the 4-character Hex code (e.g., F081)
        WITH f, 
             CASE 
                WHEN f.name CONTAINS "_DID_" THEN substring(split(f.name, "_DID_")[1], 0, 4)
                ELSE substring(split(f.name, "_RID_")[1], 0, 4)
             END AS uds_hex
        WHERE uds_hex <> ""
        
        // Create the External UDS Node and link it
        MERGE (u:UdsService {did: uds_hex})
        ON CREATE SET u:GraphNode, u.name = "UDS_" + uds_hex
        
        MERGE (f)-[:HANDLES_UDS]->(u)
        RETURN count(f) AS linked_uds
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(map_uds_query).single()
                count = result["linked_uds"] if result else 0
                logger.info(f"Successfully mapped {count} AutoSAR UDS Entry Points.")
        except Exception as e:
            logger.error(f"Failed to map UDS entry points: {e}")

        logger.info("Propagating Taint Downstream...")
        
        # Step 2: Propagate the Taint down the newly connected call trees
        taint_query = """
        // Start the path at length 0 so the Entry Point itself gets tagged
        MATCH path = (u:UdsService)<-[:HANDLES_UDS]-(entry:Function)-[:CALLS*0..10]->(downstream:Function)
        WITH DISTINCT downstream, u.did AS source_did
        SET downstream.tainted_by_uds = true
        // Use DISTINCT to prevent massive duplicate arrays if multiple paths exist
        WITH downstream, collect(DISTINCT source_did) AS uds_sources
        SET downstream.reachable_from_dids = uds_sources
        RETURN count(downstream) AS tainted_count
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(taint_query).single()
                count = result["tainted_count"] if result else 0
                logger.info(f"Successfully traced UDS taint to {count} downstream functions.")
        except Exception as e:
            logger.error(f"Failed to propagate UDS Taint: {e}")

    def _flag_dead_code(self):
        """
        Finds isolated functions (no callers, no UDS links, no Network links, no Hardware entries).
        """
        logger.info("Flagging Unreachable / Dead Code...")
        query = """
        // 1. Match all functions
        MATCH (f:Function)
        
        // 2. Ensure NO incoming CALLS, NO UDS links, NO Network links, and NOT an OS/Hardware entry
        WHERE NOT ()-[:CALLS]->(f)
          AND NOT (f)-[:HANDLES_UDS]->()
          AND NOT (f)-[:RECEIVES_SIGNAL]->()
          AND NOT (f)-[:SENDS_SIGNAL]->()
          AND coalesce(f.is_hardware_entry, false) = false
          
        // 3. Mark them!
        SET f.is_dead_code = true
        
        RETURN count(f) AS dead_count
        """
        
        try:
            with self.db.driver.session() as session:
                result = session.run(query).single()
                count = result["dead_count"] if result else 0
                logger.warning(f"Flagged {count} isolated functions as Dead Code.")
        except Exception as e:
            logger.error(f"Failed to flag Dead Code: {e}")

    def _resolve_rte_data_flow(self):
        """
        Connects Runnables via RTE. If Func A writes to 'PortX', and Func B reads from 'PortX',
        this creates a direct semantic data flow edge between them.
        """
        logger.info("Resolving RTE Port Data Flows...")
        query = """
        // Find functions calling Rte_Write and Rte_Read for the same port/element
        MATCH (writer:Function)-[:CALLS]->(w_api:Function)
        WHERE w_api.name STARTS WITH "Rte_Write_"
        
        MATCH (reader:Function)-[:CALLS]->(r_api:Function)
        WHERE r_api.name STARTS WITH "Rte_Read_"
        
        // Extract the Port_Element part of the name (e.g., Rte_Write_BatteryPort_Voltage)
        WITH writer, reader, w_api, r_api,
             substring(w_api.name, 10) AS write_port,
             substring(r_api.name, 9) AS read_port
        WHERE write_port = read_port
        
        // Connect the writer directly to the reader
        MERGE (writer)-[r:RTE_DATA_FLOW {port: write_port}]->(reader)
        RETURN count(r) AS rte_flows
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query).single()
                count = result["rte_flows"] if result else 0
                logger.info(f"Resolved {count} RTE data flow connections.")
        except Exception as e:
            logger.error(f"Failed to resolve RTE data flow: {e}")

    def _flag_dangerous_sinks(self):
        """Flags functions that are known vulnerability sinks (libc + AutoSAR variants)."""
        logger.info("Flagging Dangerous Memory and NVM Sinks...")
        query = """
        MATCH (f:Function)
        // Catch standard libc AND AutoSAR wrappers like VStdLib_MemCpy, TRNmemcpy, etc.
        WHERE toLower(f.name) CONTAINS 'memcpy'
           OR toLower(f.name) CONTAINS 'memcopy'
           OR toLower(f.name) CONTAINS 'memset'
           OR toLower(f.name) CONTAINS 'memmove'
           OR toLower(f.name) CONTAINS 'strcpy'
           OR toLower(f.name) CONTAINS 'sprintf'
           // Catch AutoSAR NVM / Flash operations
           OR f.name STARTS WITH 'NvM_Write' 
           OR f.name STARTS WITH 'Fls_Write'
        SET f.is_dangerous_sink = true
        RETURN count(f) AS sink_count
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query).single()
                count = result["sink_count"] if result else 0
                logger.info(f"Flagged {count} functions as dangerous memory sinks.")
        except Exception as e:
            logger.error(f"Failed to flag dangerous sinks: {e}")
