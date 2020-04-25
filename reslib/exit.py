"""
Compute exit status for resolve.py
"""


def exit_status(query):
    """Obtain final exit status code"""
    if query.latest_rcode is not None:
        return query.latest_rcode
    return query.response.rcode()
