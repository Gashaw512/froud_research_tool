import requests
import pandas as pd
import xml.etree.ElementTree as ET
import sqlite3
from datetime import datetime, timedelta
import re
import schedule
import time
from fuzzywuzzy import fuzz
import json
import os
from typing import Dict, List, Any, Optional

class IntegratedSanctionScreener:
    """Comprehensive sanction screening with XML parsing capabilities"""
    
    def __init__(self, db_path='cyber_fraud_platform.db'):
        self.db_conn = sqlite3.connect(db_path)
        self.setup_database()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberFraudPlatform/2.0'
        })
    
    def setup_database(self):
        """Setup unified database tables"""
        cursor = self.db_conn.cursor()
        
        # Sanction lists table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sanction_entities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                list_source TEXT,
                entity_type TEXT,
                name TEXT,
                alias TEXT,
                dob DATE,
                passport TEXT,
                nationality TEXT,
                address TEXT,
                listing_date DATE,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(list_source, name, dob)
            )
        ''')
        
        # Screening results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sanction_screening_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id TEXT,
                customer_name TEXT,
                screening_type TEXT,
                screening_date DATETIME,
                match_score REAL,
                matched_entities TEXT,
                clari5_alert_id TEXT,
                status TEXT DEFAULT 'pending',
                created_date DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Customer data table (shared with fraud detection)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS customers (
                customer_id TEXT PRIMARY KEY,
                customer_type TEXT,
                name TEXT,
                email TEXT,
                phone TEXT,
                nationality TEXT,
                risk_category TEXT,
                last_updated DATETIME,
                cyber_risk_score REAL DEFAULT 0,
                fraud_risk_score REAL DEFAULT 0
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sanction_name ON sanction_entities(name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sanction_source ON sanction_entities(list_source)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_screening_customer ON sanction_screening_results(customer_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_screening_date ON sanction_screening_results(screening_date)')
        
        self.db_conn.commit()
    
    def download_sanction_lists(self):
        """Download and update sanction lists from multiple sources"""
        print("🔄 Updating sanction lists...")
        
        sources = {
            'UN': 'https://scsanctions.un.org/resources/xml/en/consolidated.xml',
            'OFAC': 'https://www.treasury.gov/ofac/downloads/sdn.xml',
            'EU': 'https://webgate.ec.europa.eu/europeaid/fsd/fsf/public/files/xmlFullSanctionsList_1_1/content?token=12345'
        }
        
        success_count = 0
        for source, url in sources.items():
            try:
                print(f"📥 Downloading {source} sanctions...")
                response = self.session.get(url, timeout=60)
                if response.status_code == 200:
                    entities = self.parse_sanction_xml(response.content, source)
                    if entities:
                        self._store_sanction_entities(entities, source)
                        success_count += 1
                        print(f"✅ {source}: {len(entities)} entities processed")
                    else:
                        print(f"⚠️  {source}: No entities parsed from XML")
                else:
                    print(f"❌ Failed to download {source}: HTTP {response.status_code}")
            except Exception as e:
                print(f"❌ Error downloading {source}: {str(e)}")
        
        print(f"✅ Sanction list update completed: {success_count}/{len(sources)} sources updated")
        return success_count
    
    def parse_sanction_xml(self, xml_content: bytes, source: str) -> List[Dict[str, Any]]:
        """Parse XML content from sanction lists"""
        try:
            root = ET.fromstring(xml_content)
            entities = []
            
            if source == 'UN':
                entities = self._parse_un_sanctions(root)
            elif source == 'OFAC':
                entities = self._parse_ofac_sanctions(root)
            elif source == 'EU':
                entities = self._parse_eu_sanctions(root)
            else:
                print(f"⚠️  Unknown sanction source: {source}")
                entities = self._parse_generic_sanctions(root, source)
            
            # Add source information to each entity
            for entity in entities:
                entity['list_source'] = source
                entity['last_updated'] = datetime.now()
            
            return entities
            
        except ET.ParseError as e:
            print(f"❌ XML parsing error for {source}: {e}")
            return []
        except Exception as e:
            print(f"❌ Error parsing {source} XML: {e}")
            return []
    
    def _parse_un_sanctions(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Parse UN sanction list XML"""
        entities = []
        ns = {'ns': 'http://www.un.org/sanctions/1.0'}  # UN sanctions namespace
        
        try:
            # Try different possible element paths for UN sanctions
            for individual in root.findall('.//INDIVIDUAL', ns) or root.findall('.//INDIVIDUAL'):
                entity = {
                    'name': self._extract_un_name(individual),
                    'entity_type': 'individual',
                    'alias': self._extract_un_aliases(individual),
                    'dob': self._extract_un_dob(individual),
                    'passport': self._extract_un_passport(individual),
                    'nationality': self._extract_un_nationality(individual),
                    'address': self._extract_un_address(individual),
                    'listing_date': datetime.now().strftime('%Y-%m-%d')
                }
                if entity['name']:  # Only add if we have a name
                    entities.append(entity)
            
            # Also look for entities/organizations
            for entity_elem in root.findall('.//ENTITY', ns) or root.findall('.//ENTITY'):
                entity = {
                    'name': entity_elem.findtext('NAME', '').strip(),
                    'entity_type': 'entity',
                    'alias': '',
                    'dob': '',
                    'passport': '',
                    'nationality': '',
                    'address': self._extract_un_address(entity_elem),
                    'listing_date': datetime.now().strftime('%Y-%m-%d')
                }
                if entity['name']:
                    entities.append(entity)
                    
        except Exception as e:
            print(f"❌ Error parsing UN sanctions: {e}")
        
        return entities
    
    def _extract_un_name(self, individual: ET.Element) -> str:
        """Extract name from UN individual element"""
        try:
            first_name = individual.findtext('FIRST_NAME', '').strip()
            second_name = individual.findtext('SECOND_NAME', '').strip()
            third_name = individual.findtext('THIRD_NAME', '').strip()
            
            names = [name for name in [first_name, second_name, third_name] if name]
            return ' '.join(names) if names else individual.findtext('NAME', '').strip()
        except:
            return individual.findtext('NAME', '').strip()
    
    def _extract_un_aliases(self, individual: ET.Element) -> str:
        """Extract aliases from UN individual element"""
        aliases = []
        for alias in individual.findall('.//ALIAS') or []:
            alias_name = alias.findtext('ALIAS_NAME', '').strip()
            if alias_name:
                aliases.append(alias_name)
        return '; '.join(aliases) if aliases else ''
    
    def _extract_un_dob(self, individual: ET.Element) -> str:
        """Extract date of birth from UN individual element"""
        try:
            dob = individual.findtext('DATE_OF_BIRTH', '').strip()
            if dob and len(dob) >= 4:  # At least a year
                return dob
        except:
            pass
        return ''
    
    def _extract_un_passport(self, individual: ET.Element) -> str:
        """Extract passport information from UN individual element"""
        try:
            for doc in individual.findall('.//DOCUMENT') or []:
                doc_type = doc.findtext('TYPE_OF_DOCUMENT', '').strip()
                if 'PASSPORT' in doc_type.upper():
                    return doc.findtext('NUMBER', '').strip()
        except:
            pass
        return ''
    
    def _extract_un_nationality(self, individual: ET.Element) -> str:
        """Extract nationality from UN individual element"""
        try:
            nationality = individual.findtext('NATIONALITY', '').strip()
            if nationality:
                return nationality
                
            # Alternative location for nationality
            for nationality_elem in individual.findall('.//NATIONALITY') or []:
                country = nationality_elem.findtext('COUNTRY', '').strip()
                if country:
                    return country
        except:
            pass
        return ''
    
    def _extract_un_address(self, element: ET.Element) -> str:
        """Extract address from UN element"""
        try:
            address = element.findtext('ADDRESS', '').strip()
            if address:
                return address
                
            # Alternative location for address
            for address_elem in element.findall('.//ADDRESS') or []:
                street = address_elem.findtext('STREET', '').strip()
                city = address_elem.findtext('CITY', '').strip()
                country = address_elem.findtext('COUNTRY', '').strip()
                
                address_parts = [part for part in [street, city, country] if part]
                if address_parts:
                    return ', '.join(address_parts)
        except:
            pass
        return ''
    
    def _parse_ofac_sanctions(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Parse OFAC sanction list XML"""
        entities = []
        
        try:
            # OFAC SDN list structure
            for entry in root.findall('.//sdnEntry'):
                entity = {
                    'name': self._extract_ofac_name(entry),
                    'entity_type': self._extract_ofac_type(entry),
                    'alias': self._extract_ofac_aliases(entry),
                    'dob': self._extract_ofac_dob(entry),
                    'passport': '',
                    'nationality': self._extract_ofac_nationality(entry),
                    'address': self._extract_ofac_address(entry),
                    'listing_date': datetime.now().strftime('%Y-%m-%d')
                }
                if entity['name']:
                    entities.append(entity)
                    
        except Exception as e:
            print(f"❌ Error parsing OFAC sanctions: {e}")
        
        return entities
    
    def _extract_ofac_name(self, entry: ET.Element) -> str:
        """Extract name from OFAC entry"""
        try:
            first_name = entry.findtext('firstName', '').strip()
            last_name = entry.findtext('lastName', '').strip()
            
            if first_name and last_name:
                return f"{first_name} {last_name}"
            elif last_name:
                return last_name
            else:
                return entry.findtext('lastName', '').strip()
        except:
            return entry.findtext('lastName', '').strip()
    
    def _extract_ofac_type(self, entry: ET.Element) -> str:
        """Extract entity type from OFAC entry"""
        try:
            sdn_type = entry.findtext('sdnType', '').strip()
            if sdn_type:
                return sdn_type.lower()
        except:
            pass
        return 'individual'
    
    def _extract_ofac_aliases(self, entry: ET.Element) -> str:
        """Extract aliases from OFAC entry"""
        aliases = []
        try:
            for aka in entry.findall('.//aka') or []:
                aka_name = aka.findtext('akaName', '').strip()
                if aka_name:
                    aliases.append(aka_name)
        except:
            pass
        return '; '.join(aliases) if aliases else ''
    
    def _extract_ofac_dob(self, entry: ET.Element) -> str:
        """Extract date of birth from OFAC entry"""
        try:
            for date_of_birth in entry.findall('.//dateOfBirth') or []:
                dob = date_of_birth.findtext('dateOfBirthItem', '').strip()
                if dob:
                    return dob
        except:
            pass
        return ''
    
    def _extract_ofac_nationality(self, entry: ET.Element) -> str:
        """Extract nationality from OFAC entry"""
        try:
            for nationality in entry.findall('.//nationality') or []:
                country = nationality.findtext('country', '').strip()
                if country:
                    return country
        except:
            pass
        return ''
    
    def _extract_ofac_address(self, entry: ET.Element) -> str:
        """Extract address from OFAC entry"""
        try:
            for address in entry.findall('.//address') or []:
                address1 = address.findtext('address1', '').strip()
                city = address.findtext('city', '').strip()
                country = address.findtext('country', '').strip()
                
                address_parts = [part for part in [address1, city, country] if part]
                if address_parts:
                    return ', '.join(address_parts)
        except:
            pass
        return ''
    
    def _parse_eu_sanctions(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Parse EU sanction list XML"""
        entities = []
        
        try:
            # EU sanctions structure
            for sanctioned_entity in root.findall('.//SANCTIONED_ENTITY') or root.findall('.//Entity'):
                entity = {
                    'name': sanctioned_entity.findtext('NAME', '').strip(),
                    'entity_type': sanctioned_entity.findtext('TYPE', 'entity').strip(),
                    'alias': sanctioned_entity.findtext('ALIAS', '').strip(),
                    'dob': sanctioned_entity.findtext('DATE_OF_BIRTH', '').strip(),
                    'passport': sanctioned_entity.findtext('PASSPORT', '').strip(),
                    'nationality': sanctioned_entity.findtext('NATIONALITY', '').strip(),
                    'address': sanctioned_entity.findtext('ADDRESS', '').strip(),
                    'listing_date': datetime.now().strftime('%Y-%m-%d')
                }
                if entity['name']:
                    entities.append(entity)
                    
        except Exception as e:
            print(f"❌ Error parsing EU sanctions: {e}")
        
        return entities
    
    def _parse_generic_sanctions(self, root: ET.Element, source: str) -> List[Dict[str, Any]]:
        """Generic XML parsing for unknown sanction list formats"""
        entities = []
        
        try:
            # Look for common element names
            for elem in root.findall('.//Entity') or root.findall('.//INDIVIDUAL') or root.findall('.//ENTRY'):
                entity = {
                    'name': self._extract_text_from_element(elem, ['Name', 'NAME', 'firstName', 'FIRST_NAME']),
                    'entity_type': self._extract_text_from_element(elem, ['Type', 'TYPE', 'entityType']),
                    'alias': self._extract_text_from_element(elem, ['Alias', 'ALIAS', 'aka']),
                    'dob': self._extract_text_from_element(elem, ['DateOfBirth', 'DATE_OF_BIRTH', 'dob']),
                    'passport': self._extract_text_from_element(elem, ['Passport', 'PASSPORT']),
                    'nationality': self._extract_text_from_element(elem, ['Nationality', 'NATIONALITY', 'country']),
                    'address': self._extract_text_from_element(elem, ['Address', 'ADDRESS']),
                    'listing_date': datetime.now().strftime('%Y-%m-%d')
                }
                if entity['name']:
                    entities.append(entity)
                    
        except Exception as e:
            print(f"❌ Error parsing generic {source} sanctions: {e}")
        
        return entities
    
    def _extract_text_from_element(self, element: ET.Element, tag_options: List[str]) -> str:
        """Extract text from element using multiple possible tag names"""
        for tag in tag_options:
            text = element.findtext(tag, '').strip()
            if text:
                return text
        return ''
    
    def _store_sanction_entities(self, entities: List[Dict[str, Any]], source: str) -> None:
        """Store sanction entities in database"""
        cursor = self.db_conn.cursor()
        
        for entity in entities:
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO sanction_entities 
                    (list_source, entity_type, name, alias, dob, passport, nationality, address, listing_date, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    source,
                    entity.get('entity_type', 'individual'),
                    entity.get('name', ''),
                    entity.get('alias', ''),
                    entity.get('dob', ''),
                    entity.get('passport', ''),
                    entity.get('nationality', ''),
                    entity.get('address', ''),
                    entity.get('listing_date', ''),
                    datetime.now()
                ))
            except Exception as e:
                print(f"❌ Error storing entity {entity.get('name', 'Unknown')}: {e}")
        
        self.db_conn.commit()
    
    def screen_customer_onboarding(self, customer_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Screen new customer during onboarding"""
        print(f"🔍 Screening new customer: {customer_data.get('name', 'Unknown')}")
        
        # Store customer data
        self.store_customer_data(customer_data)
        
        # Perform screening
        matches = self.perform_screening(customer_data, "onboarding")
        
        # Store results
        if matches:
            self.store_screening_result(customer_data, matches, "SYSTEM_ALERT", "onboarding")
        
        return matches
    
    def perform_screening(self, customer_data: Dict[str, Any], screening_type: str) -> List[Dict[str, Any]]:
        """Perform actual sanction screening"""
        cursor = self.db_conn.cursor()
        cursor.execute('SELECT * FROM sanction_entities')
        sanction_entities = []
        
        # Convert rows to dictionaries
        for row in cursor.fetchall():
            sanction_entities.append(dict(zip([col[0] for col in cursor.description], row)))
        
        matches = []
        for entity in sanction_entities:
            match_score = self.calculate_match_score(customer_data, entity)
            
            if match_score >= 0.8:  # Configurable threshold
                matches.append({
                    'sanction_entity': entity,
                    'match_score': match_score,
                    'matched_fields': self.get_matched_fields(customer_data, entity)
                })
        
        return matches
    
    def calculate_match_score(self, customer_data: Dict[str, Any], sanction_entity: Dict[str, Any]) -> float:
        """Calculate match score using fuzzy matching"""
        scores = []
        weights = {'name': 0.6, 'nationality': 0.2, 'dob': 0.2}
        
        # Name matching
        customer_name = customer_data.get('name', '').lower()
        sanction_name = sanction_entity.get('name', '').lower()
        
        if customer_name and sanction_name:
            name_score = fuzz.partial_ratio(customer_name, sanction_name) / 100
            scores.append(name_score * weights['name'])
        
        # Nationality matching
        customer_nationality = customer_data.get('nationality', '').lower()
        sanction_nationality = sanction_entity.get('nationality', '').lower()
        
        if customer_nationality and sanction_nationality:
            nationality_score = 1.0 if customer_nationality == sanction_nationality else 0.0
            scores.append(nationality_score * weights['nationality'])
        
        # Date of birth matching (simplified)
        customer_dob = customer_data.get('dob', '')
        sanction_dob = sanction_entity.get('dob', '')
        
        if customer_dob and sanction_dob:
            # Simple year matching for demonstration
            customer_year = customer_dob[:4] if len(customer_dob) >= 4 else ''
            sanction_year = sanction_dob[:4] if len(sanction_dob) >= 4 else ''
            
            if customer_year and sanction_year and customer_year == sanction_year:
                scores.append(1.0 * weights['dob'])
        
        return sum(scores) if scores else 0.0
    
    def get_matched_fields(self, customer_data: Dict[str, Any], sanction_entity: Dict[str, Any]) -> List[str]:
        """Determine which fields matched between customer and sanction entity"""
        matched_fields = []
        
        # Name matching
        if fuzz.partial_ratio(
            customer_data.get('name', '').lower(),
            sanction_entity.get('name', '').lower()
        ) > 80:
            matched_fields.append('name')
        
        # Nationality matching
        if (customer_data.get('nationality') and sanction_entity.get('nationality') and
            customer_data['nationality'].lower() == sanction_entity['nationality'].lower()):
            matched_fields.append('nationality')
        
        # Date of birth matching
        customer_dob = customer_data.get('dob', '')
        sanction_dob = sanction_entity.get('dob', '')
        if customer_dob and sanction_dob and customer_dob[:4] == sanction_dob[:4]:
            matched_fields.append('dob')
        
        return matched_fields
    
    def store_customer_data(self, customer_data: Dict[str, Any]) -> None:
        """Store customer data in the database"""
        cursor = self.db_conn.cursor()
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO customers 
                (customer_id, customer_type, name, email, phone, nationality, risk_category, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                customer_data.get('customer_id', ''),
                customer_data.get('customer_type', 'individual'),
                customer_data.get('name', ''),
                customer_data.get('email', ''),
                customer_data.get('phone', ''),
                customer_data.get('nationality', ''),
                customer_data.get('risk_category', 'low'),
                datetime.now()
            ))
            self.db_conn.commit()
        except Exception as e:
            print(f"❌ Error storing customer data: {e}")
    
    def store_screening_result(self, customer_data: Dict[str, Any], matches: List[Dict[str, Any]], 
                             alert_id: str, screening_type: str) -> None:
        """Store screening result in the database"""
        cursor = self.db_conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO sanction_screening_results 
                (customer_id, customer_name, screening_type, screening_date, match_score, matched_entities, clari5_alert_id, created_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                customer_data.get('customer_id', ''),
                customer_data.get('name', ''),
                screening_type,
                datetime.now(),
                max(m['match_score'] for m in matches) if matches else 0,
                json.dumps(matches, default=str),
                alert_id,
                datetime.now()
            ))
            self.db_conn.commit()
        except Exception as e:
            print(f"❌ Error storing screening result: {e}")
    
    def get_screening_statistics(self) -> Dict[str, Any]:
        """Get screening statistics"""
        cursor = self.db_conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM sanction_entities')
        sanction_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(DISTINCT list_source) FROM sanction_entities')
        source_count = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(*) FROM sanction_screening_results 
            WHERE screening_date > datetime('now', '-1 day')
        ''')
        daily_screenings = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(*) FROM sanction_screening_results 
            WHERE match_score >= 0.8 AND screening_date > datetime('now', '-1 day')
        ''')
        daily_matches = cursor.fetchone()[0]
        
        return {
            'sanction_entities_count': sanction_count,
            'sanction_sources_count': source_count,
            'daily_screenings': daily_screenings,
            'daily_matches': daily_matches,
            'last_updated': datetime.now().isoformat()
        }
    
    def cleanup_old_data(self, days_old: int = 90) -> None:
        """Clean up old screening results"""
        cursor = self.db_conn.cursor()
        cutoff_date = (datetime.now() - timedelta(days=days_old)).strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute('DELETE FROM sanction_screening_results WHERE created_date < ?', (cutoff_date,))
        deleted_count = cursor.rowcount
        
        self.db_conn.commit()
        print(f"🧹 Cleaned up {deleted_count} screening results older than {days_old} days")

# Test function
def test_sanction_screener():
    """Test the sanction screener functionality"""
    screener = IntegratedSanctionScreener('test_sanction.db')
    
    # Test customer data
    test_customer = {
        'customer_id': 'TEST_001',
        'name': 'John Smith',
        'email': 'john.smith@example.com',
        'phone': '+1234567890',
        'nationality': 'US',
        'customer_type': 'individual',
        'risk_category': 'medium'
    }
    
    # Perform screening
    matches = screener.screen_customer_onboarding(test_customer)
    print(f"🔍 Screening completed: {len(matches)} matches found")
    
    # Get statistics
    stats = screener.get_screening_statistics()
    print(f"📊 Sanction entities: {stats['sanction_entities_count']}")
    print(f"📊 Daily screenings: {stats['daily_screenings']}")
    
    # Cleanup
    screener.cleanup_old_data(1)

if __name__ == "__main__":
    test_sanction_screener()