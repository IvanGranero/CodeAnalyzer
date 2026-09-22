import logging
import re
import xml.etree.ElementTree as ET
from tools.ingestion.builder import GraphPayloadBuilder

logger = logging.getLogger(__name__)

class ARXMLParser:
    def __init__(self, builder: GraphPayloadBuilder):
        self.builder = builder

    def parse(self, filepath: str):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                raw_xml = f.read()
                
            
            
            clean_xml = re.sub(r'\sxmlns="[^"]+"', '', raw_xml, count=1)
            root = ET.fromstring(clean_xml)
            
            uri = f"file://{filepath}"
            self._extract_os_configuration(root, uri)
            logger.info(f"Successfully parsed OS/ECUC configurations from {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to parse ARXML file {filepath}: {e}")

    def _extract_os_configuration(self, root: ET.Element, uri: str):
        for container in root.findall('.//ECUC-CONTAINER-VALUE'):
            def_ref_node = container.find('DEFINITION-REF')
            if def_ref_node is None or not def_ref_node.text:
                continue
                
            def_ref = def_ref_node.text
            short_name_node = container.find('SHORT-NAME')
            if short_name_node is None or not short_name_node.text:
                continue
                
            short_name = short_name_node.text

            if def_ref.endswith('/OsTask'):
                priority = self._get_parameter_value(container, 'OsTaskPriority') or "0"
                activation = self._get_parameter_value(container, 'OsTaskActivation') or "1"
                self.builder.add_os_entity(
                    entity_type="OsTask", 
                    name=short_name, 
                    uri=uri, 
                    properties={"priority": int(priority), "max_activations": int(activation)}
                )

            elif def_ref.endswith('/OsIsr'):
                category = self._get_parameter_value(container, 'OsIsrCategory') or "2"
                self.builder.add_os_entity(
                    entity_type="OsIsr", 
                    name=short_name, 
                    uri=uri,
                    properties={"isr_category": category}
                )

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
        
        for param in container.findall('.//ECUC-NUMERICAL-PARAM-VALUE') + container.findall('.//ECUC-TEXTUAL-PARAM-VALUE'):
            def_ref = param.find('DEFINITION-REF')
            if def_ref is not None and def_ref.text and def_ref.text.endswith(f'/{param_name}'):
                val_node = param.find('VALUE')
                if val_node is not None:
                    return val_node.text
        return None
