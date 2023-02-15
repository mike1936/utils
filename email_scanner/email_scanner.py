from __future__ import annotations

import email
import email.header
import email.message
import hashlib
import io
import os
import pathlib
import poplib
import re
from typing import Iterable, List, Tuple

import pandas as pd
from loguru import logger


POP3_SERVER_CONFIGS = {
    'default': ("USER_NAME", "PASSWORD", "SERVER_ADDRESS"),
}
SCAN_EMAIL_RECEIVED_NO_OLDER_THAN = '2023-02-10 19:00:00'


def get_email_access_keys(config_name) -> Tuple[str, str, str]:
    access_keys = POP3_SERVER_CONFIGS.get(config_name, None)
    if not access_keys:
        raise Exception(f'no such config: {config_name}')
    return access_keys


def read_last_lines_until(file_path, stop_condition) -> List[str]:
    """BUG: 文件多于一行且最后一行为空格时, 会导致死循环"""
    lines = []
    with open(file_path, 'rb') as file:
        try:
            file.seek(-1, os.SEEK_END)
        except OSError:
            file.seek(0)
        finished = False
        while (not finished):
            while file.read(1) != b'\n':
                try:
                    file.seek(-2, os.SEEK_CUR)
                except:
                    try:
                        file.seek(-1, os.SEEK_CUR)
                    except:
                        pass
                    finished = True
                    break
            line: str = file.readline().decode(encoding='gb18030')
            lines.append(line.strip())
            if stop_condition(line.strip(), lines):
                break
            try:
                file.seek(-len(line) * 2, os.SEEK_CUR)
            except:
                break
    return lines


def read_last_non_blank_line(file_path) -> str:
    stop_condition = lambda line, lines: line != '' and len(lines) >= 1
    lines = read_last_lines_until(file_path, stop_condition)
    non_blank_lines = [line for line in lines if line != '']
    if len(non_blank_lines):
        return non_blank_lines[0]
    else:
        return ''


class EmailScanner:

    """邮件扫描器"""

    scan_no_older_than = pd.to_datetime(str(SCAN_EMAIL_RECEIVED_NO_OLDER_THAN))
        # 初次扫描(无hash_log)时，读取到第一个早于该时间的邮件就停止扫描

    hash_log_file = pathlib.Path(__file__).parent.joinpath('batch_history.log')
        # 记录每批扫描第一封（最新）的邮件的md5hash值的历史

    hash_log_header = 'scan_time,last_scaned_email_md5,email_received_time,email_subject'
        # hash_log内csv值对应的含义, 实际记录文件不包含该行（为了方便解析）

    def __init__(self):
        self.user, self.passwd, self.server_addr = get_email_access_keys('default')

    @property
    def last_scanned_email_hash_value(self) -> str:
        if not self.hash_log_file.exists():
            return ''
        line = read_last_non_blank_line(self.hash_log_file)
        if line == '' or len(line.split(',')) < 2:
            return ''
        res = re.match(r'(?P<md5>[0-9a-f]{32})', line.split(',')[1])
        if not res:
            return ''
        return res['md5']

    def login(self):
        server = poplib.POP3(self.server_addr)
        server.set_debuglevel(0)
        server.user(self.user)
        server.pass_(self.passwd)
        self.server = server
        if self.server is None:
            raise Exception("Can't login to server")

    @property
    def email_count(self) -> int:
        resp, mails, octets = self.server.list()
        return len(mails)

    def get_email_by_index(self, index) -> Email | None:
        try:
            return Email(self.server, index)
        except:
            logger.exception(f"Error Retreving/Parsing Email {index}")
            return None

    def emails_need_scanned(self) -> Iterable[Email]:
        """扫描所有email"""
        email_count = self.email_count # 当前所有邮件
        indexes = range(email_count, 0, -1)
        cur_index, cur_hash, cur_email = None, None, None
        latest_index, latest_hash, latest_email = None, None, None # 记录的Email，记录最新一封
        if len(indexes) == 0:
            logger.warning('POP3服务器无邮件')
            return

        scanned_emails: List[Tuple[bool, int, pd.Timestamp | None, str]] = []
            # list of tuple of (success, index, received_time, subject)

        for index in indexes: # 从最新一封开始，倒序遍历
            my_email = self.get_email_by_index(index)

            # 未解析成功
            if my_email is None:
                scanned_emails.append((False, index, None, '')) # 记录失败的
                continue
        
            # 超过历史获取限制
            if my_email.received_time < self.scan_no_older_than:
                break

            cur_index, cur_hash, cur_email = index, my_email.md5, my_email

            # 匹配到上一批次成功扫描的第一封（最新）的邮件, 退出
            if cur_hash == self.last_scanned_email_hash_value:
                break

            if (latest_index, latest_hash, latest_email) == (None, None, None):
                latest_index, latest_hash, latest_email = cur_index, cur_hash, cur_email # 记录的Email，记录最新一封
            subject_str = cur_email.subject
            subject_str = subject_str.ljust(10, ' ') if len(subject_str) <= 10 else subject_str[:7] + '...'
            received_time_str = cur_email.received_time.strftime(r"%Y-%m-%d %H:%M:%S")
            hint = f'Scaning Email[{index}][{cur_hash[:4]}...{cur_hash[-4:]}] - {received_time_str} - {subject_str}'
            logger.info(hint)

            scanned_emails.append((True, cur_index, cur_email.received_time, cur_email.subject))# 记录成功的
            yield cur_email
            # self.jot_hash_value(cur_hash, cur_email.received_time, cur_email.subject)
            #   # 记录每一条Note如果使用该方式 日志可能很长

        if (latest_index, latest_hash, latest_email) != (None, None, None):
            if latest_index is None or latest_hash is None or latest_email is None:
                logger.bind(name='email_admin').error('无可记录的email')
                raise Exception('无可记录的email')
            # 扫描后记录最后一个
            self.jot_hash_value(latest_hash, latest_email.received_time, latest_email.subject)
        
        # 汇报该批次扫描的错误(如有)
        if any([not scanned_email[0] for scanned_email in scanned_emails]):
            error_msg_rows = [
                'EmailIndex HasError ReceiveTime         Subject'
            ] + [
                (
                    f'{scanned_email[1]:<10} '
                    f'{"" if scanned_email[0] else "Yes":>8} '
                    f'{scanned_email[2].strftime(r"%Y-%m-%d %H:%M:%S") if scanned_email[2] else ""} '
                    f'{scanned_email[3]}'
                )
                for scanned_email in scanned_emails
            ]
            msg = 'Email Scanner Batch Includes Error, Details:\n' + '\n'.join(error_msg_rows)
            logger.bind(name="email_admin").error(msg)

    def jot_hash_value(self, md5_hash_str, received_time, email_subject):
        scan_time_str = pd.Timestamp.now().strftime(r"%Y-%m-%d %H:%M:%S")
        received_time_str = received_time.strftime(r"%Y-%m-%d %H:%M:%S")
        line = f'{scan_time_str},{md5_hash_str},{received_time_str},{email_subject}'
        if not self.hash_log_file.exists():
            with open(self.hash_log_file, 'w', encoding='gb18030') as f:
                f.write(line + '\n')
        else:
            with open(self.hash_log_file, 'a', encoding='gb18030') as f:
                f.write(line + '\n')

    def start(self):
        processors_classes = EmailProcessorBase.__subclasses__()
        for my_email in self.emails_need_scanned():
            for cls in processors_classes:
                processor = cls()
                if processor.is_target_email(my_email):
                    processor.process_email(my_email)


class EmailProcessorBase:

    """邮件处理器基础类"""

    def is_target_email(self, my_email) -> bool:
        """判断当前扫描的Email是否需要被Processor处理"""
        raise NotImplementedError()

    def process_email(self, my_email):
        """对is_target_email为True的my_email执行该操作"""
        raise NotImplementedError()


class EmailProcessorExample(EmailProcessorBase):

    """邮件处理器 示例"""

    attachment_save_folder = pathlib.Path(__file__).parent.joinpath('attachments')

    def is_target_email(self, my_email) -> bool:
        email_reg_exp = r"目标邮件正则表达式"
        if re.match(email_reg_exp, my_email.subject) is None:
            return False
        if my_email.sender != 'target-sender@example.com':
            return False
        return True

    def process_email(self, my_email):
        for attachment in my_email.attachments:
            if self.is_target_attachment(attachment):
                logger.info("Matched Attachment:", attachment.file_name)
                attachment.save_to(self.attachment_save_folder)
                self.process_data(attachment)
                break

    def process_data(self, attachment: EmailAttachment):
        """附件数据处理逻辑"""
        df = pd.read_excel(attachment.as_BytesIO())
        print(df.head())

    def is_target_attachment(self, attachment):
        attachment_file_name_reg_exp = r"目标附件正则表达式.xlsx"
        if re.match(attachment_file_name_reg_exp, attachment.file_name) is None:
            return False
        return True


class Email:

    def __init__(self, server, index):
        self.index = index
        message = self.retreive_message(server, index)
        self.message = message
        self.received_time:pd.Timestamp = self.parse_received_time(message)
        self.subject:str = self.parse_subject(message)
        self.attachments:List[EmailAttachment] = self.parse_attachments(message)
        self.sender:str = self.parse_sender(message)

    @property
    def md5(self) -> str:
        m = hashlib.md5()
        m.update(self.message.as_bytes())
        return m.hexdigest()

    def retreive_message(self, server, index) -> email.message.Message:
        resp, lines, octets = server.retr(self.index)
        if not re.match(r'\+OK\s\d+', resp.decode()):
            raise Exception(f'无法从server正确获取邮件内容, index: {index}')
        msg_content_bytes = b'\r\n'.join(lines)
        message = email.message_from_bytes(msg_content_bytes)
        return message

    def parse_sender(self, message:email.message.Message) -> str:
        try:
            from_ = message.get('From')
            result = re.match(r'.*?<?([\d\w_\.-]*@[\d\w_\.-]*)>?', from_)
            return result[1] if result else ''
        except:
            return ''

    def parse_received_time(self, message:email.message.Message) -> pd.Timestamp:
        regexp_list = [
            r"(\w{3},\s?\d+\s\w{3}\s\d{4}\s\d{1,2}:\d{2}:\d{2}\s\+\d{4})",
                # Eg: Wed, 11 Aug 2021 09:20:13 +0800
                # or  Fri, 3 Feb 2023 0:34:59 +0800
            r"(\d+\s\w{3}\s\d{4}\s\d{2}:\d{2}:\d{2}\s\+\d{4})",
                # Eg: 10 Aug 2021 17:38:53 +0800
        ]
        date_str = message.get('Received')
        if not date_str:
            date_str = message.get('Date')
        t = None
        for pattern in regexp_list:
            match_result = re.search(pattern, date_str)
            if match_result is not None:
                t = pd.to_datetime(match_result[1])
                break
        if t is None:
            raise Exception('Error_parsing received time %s' % date_str)
        if t.tzinfo:
            t = t.tz_convert('Asia/Shanghai')
        t = t.tz_localize(None)
        return t

    def parse_subject(self, message:email.message.Message) -> str:
        return self.decode(message.get('Subject'))

    def parse_attachments(self, message:email.message.Message) -> list:
        attachments = []
        for message_part in message.walk():
            filename_content = message_part.get_filename()
            if filename_content is not None:
                filename = self.decode(filename_content)
                filename = filename.replace(r'\r\n', '')
                filebytes = message_part.get_payload(decode=True)
                attachment = EmailAttachment(filename, filebytes)
                attachments.append(attachment)
        return attachments

    def decode(self, content_str) -> str:
        header, encoding_format = email.header.decode_header(content_str)[0]
        if isinstance(header, bytes) and encoding_format is not None:
            try:
                return header.decode(encoding_format)
            except LookupError:
                return header.decode('utf-8')
            except UnicodeDecodeError:
                return header.decode('gb18030')
        if isinstance(header, str):
            return header
        raise Exception('无法解码的内容')


class EmailAttachment:

    def __init__(self, file_name, file_bytes):
        self.file_name = file_name
        self.file_bytes = file_bytes

    def as_BytesIO(self) -> io.BytesIO:
        return io.BytesIO(self.file_bytes)

    def save_to(self, folder: pathlib.Path):
        if not folder.exists():
            folder.mkdir()
        path = os.path.join(folder, self.file_name)
        with open(path, 'wb') as f:
            f.write(self.file_bytes)


if __name__ == "__main__":
    es = EmailScanner()
    es.login()
    es.start()
