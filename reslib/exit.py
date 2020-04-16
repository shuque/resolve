"""
Compute exit status for resolve.py
"""


def exit_status(query):
    """Obtain final exit status code"""
    if query.cname_chain:
        last_cname = query.cname_chain.pop()
        rcode = last_cname.rcode
        got_answer = last_cname.got_answer
    else:
        rcode = query.rcode
        got_answer = query.got_answer

    if rcode == 0 and got_answer:
        return 0
    return 1
