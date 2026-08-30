import logging
import re
import xml.etree.ElementTree as ET
from ingest.builder import GraphPayloadBuilder

logger = logging.getLogger(__name__)

class ARXMLParser:
    def __init__(self, builder: GraphPayloadBuilder):
        self.builder = builder

    def parse(self, filepath: str):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                raw_xml = f.read()
                
            # ARXML namespaces are notoriously strict and version-dependent.
            # Stripping them out entirely makes parsing 100x easier and robust across vendors.
            clean_xml = re.sub(r'\sxmlns="[^"]+"', '', raw_xml, count=1)
            root = ET.fromstring(clean_xml)
            
            uri = f"file://{filepath}"
            self._extract_os_configuration(root, uri)
            logger.info(f"Successfully parsed OS/ECUC configurations from {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to parse ARXML file {filepath}: {e}")

    def _extract_os_configuration(self, root: ET.Element, uri: str):
        """
        AUTOSAR OS configurations are stored in ECUC-CONTAINER-VALUE blocks.
        We look for specific DEFINITION-REFs that indicate Tasks, ISRs, and Resources.
        """
        # Find all ECUC containers anywhere in the document
        for container in root.findall('.//ECUC-CONTAINER-VALUE'):
            def_ref_node = container.find('DEFINITION-REF')
            if def_ref_node is None or not def_ref_node.text:
                continue
                
            def_ref = def_ref_node.text
            short_name_node = container.find('SHORT-NAME')
            if short_name_node is None or not short_name_node.text:
                continue
                
            short_name = short_name_node.text

            # 1. Extract OS Tasks
            if def_ref.endswith('/OsTask'):
                priority = self._get_parameter_value(container, 'OsTaskPriority') or "0"
                activation = self._get_parameter_value(container, 'OsTaskActivation') or "1"
                self.builder.add_os_entity(
                    entity_type="OsTask", 
                    name=short_name, 
                    uri=uri, 
                    properties={"priority": int(priority), "max_activations": int(activation)}
                )

            # 2. Extract OS Interrupts (ISRs)
            elif def_ref.endswith('/OsIsr'):
                category = self._get_parameter_value(container, 'OsIsrCategory') or "2"
                self.builder.add_os_entity(
                    entity_type="OsIsr", 
                    name=short_name, 
                    uri=uri,
                    properties={"isr_category": category}
                )

            # 3. Extract OS Resources (Mutexes/Spinlocks)
            elif def_ref.endswith('/OsResource'):
                res_property = self._get_parameter_value(container, 'OsResourceProperty') or "STANDARD"
                self.builder.add_os_entity(
                    entity_type="OsResource", 
                    name=short_name, 
                    uri=uri,
                    properties={"resource_property": res_property}
                )

    def _get_parameter_value(self, container: ET.Element, param_name: str) -> str:
        """Helper to dig into AUTOSAR parameter values."""
        # Check numerical/text parameters
        for param in container.findall('.//ECUC-NUMERICAL-PARAM-VALUE') + container.findall('.//ECUC-TEXTUAL-PARAM-VALUE'):
            def_ref = param.find('DEFINITION-REF')
            if def_ref is not None and def_ref.text and def_ref.text.endswith(f'/{param_name}'):
                val_node = param.find('VALUE')
                if val_node is not None:
                    return val_node.text
        return None
