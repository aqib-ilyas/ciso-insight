"""Product database CSV parser for SHA1-based vulnerability lookup."""
import csv
import logging
from typing import Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class ProductDatabase:
    """Parser for product database CSV file."""

    def __init__(self, csv_path: str = "data.csv"):
        self.csv_path = Path(csv_path)
        self.products = {}
        self._load_database()

    def _load_database(self):
        """Load product database from CSV file."""
        try:
            if not self.csv_path.exists():
                logger.warning(f"Product database not found: {self.csv_path}")
                return

            with open(self.csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    company = row.get('company_name', '').strip()
                    product = row.get('product_name', '').strip()
                    sha1 = row.get('sha1', '').strip()

                    if product and sha1:
                        # Store by product name (case-insensitive)
                        key = product.lower()
                        self.products[key] = {
                            'company_name': company,
                            'product_name': product,
                            'sha1': sha1,
                        }

            logger.info(f"Loaded {len(self.products)} products from database")

        except Exception as e:
            logger.error(f"Failed to load product database: {str(e)}")
            self.products = {}

    def lookup_product(self, product_name: str) -> Optional[Dict[str, Any]]:
        """
        Look up product in database by name.

        Args:
            product_name: Product name to search for

        Returns:
            Dict with company_name, product_name, sha1 if found, None otherwise
        """
        if not product_name:
            return None

        # Try exact match first (case-insensitive)
        key = product_name.lower().strip()
        if key in self.products:
            logger.info(f"Found {product_name} in product database with SHA1: {self.products[key]['sha1']}")
            return self.products[key]

        # Try partial match (product name contains the search term or vice versa)
        for stored_key, product_data in self.products.items():
            if key in stored_key or stored_key in key:
                logger.info(
                    f"Found partial match for {product_name}: "
                    f"{product_data['product_name']} with SHA1: {product_data['sha1']}"
                )
                return product_data

        logger.info(f"Product {product_name} not found in database, will use latest version")
        return None

    def get_all_products(self) -> Dict[str, Dict[str, Any]]:
        """Get all products in the database."""
        return self.products.copy()

    def get_product_count(self) -> int:
        """Get total number of products in database."""
        return len(self.products)
