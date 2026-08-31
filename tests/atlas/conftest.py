from pathlib import Path

import pytest
import yaml


HERE = Path(__file__).parent
DATA_DIR = HERE / 'data'
ATLAS_YAML = DATA_DIR / 'atlas.yaml'


with ATLAS_YAML.open('r') as fb:
    ATLAS = yaml.load(fb, Loader=yaml.Loader)


@pytest.fixture
def atlas_data():
    return ATLAS
