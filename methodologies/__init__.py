"""Taint calculation methodology strategies.

Each module exposes a `calculate_taint()` function with signature:
    calculate_taint(tainted_input_value, total_input_value, outputs) -> list[float]

Returns a list of taint percentages, one per output.
"""

from methodologies.poison import calculate_taint as poison
from methodologies.haircut import calculate_taint as haircut
from methodologies.pro_rata import calculate_taint as pro_rata

METHODOLOGIES = {
    "poison": poison,
    "haircut": haircut,
    "pro_rata": pro_rata,
}
