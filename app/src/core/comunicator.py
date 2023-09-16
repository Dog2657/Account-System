from .templator import render

def send_email_template(
    templateName: str,
    to: str,
    subject: str,
    cc: str = None,
    bcc: str = None,
    **templateData,
):
    body = render(f'emails/{templateName}', **templateData)

    print(f'\n------------ Email Start ------------\nTo: {to}\nCC: {cc}\nBCC: {bcc}\nSubject: {subject }\n\n{body}\n------------- Email End -------------\n')

    #TODO: add email send code


def send_email(
    to: str,
    subject: str,
    cc: str = None,
    bcc: str = None,
    html: str = None,
    text: str = None
):
    print(f'\n------------ Email Start ------------\nTo: {to}\nCC: {cc}\nBCC: {bcc}\nSubject: {subject}\n\n{f"(html) {html}" or text}\n------------- Email End -------------\n')
    #TODO: add email send code



def send_sms_template(
    templateName: str,
    to: str,
    **templateData
):
    body = render(f'sms/{templateName}', **templateData)

    print(f'\n------------ SMS Start ------------\nTo: {to}\n\n{body}\n------------- SMS End -------------\n')    
    #TODO: add sms send code


def send_sms(
    to: str,
    body: str
):
    print(f'\n------------ SMS Start ------------\nTo: {to}\n\n{body}\n------------- SMS End -------------\n')
    #TODO: add sms send code