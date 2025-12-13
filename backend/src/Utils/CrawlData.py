import requests
from bs4 import BeautifulSoup
import pandas as pd
import os

BASE_URL = 'https://bazaar.abuse.ch/'


def crawl_bazaar(limit: int = 10, save_path: str = "./data/data.csv"):
    item_urls = []
    names = []

    # Lấy danh sách sample
    page = requests.get(BASE_URL + 'browse/')
    soup = BeautifulSoup(page.content, 'html.parser')

    data = soup.select('#samples > tbody > tr')[:limit]  # giới hạn số lượng
    for item in data:
        sha256 = item.select('td')[1].get_text()
        signature = item.select('td')[3].get_text()
        item_urls.append(BASE_URL + 'sample/' + sha256)
        names.append(signature)

    # Chuẩn bị danh sách dữ liệu
    sha256_list, sha3_384_list, sha1_list, md5_list = [], [], [], []
    file_type_list, mime_type_list, firstseen_list = [], [], []

    # Crawl từng sample
    for url in item_urls:
        page = requests.get(url)
        soup = BeautifulSoup(page.content, 'html.parser')

        sha256_list.append(soup.select_one('#sha256_hash').get_text())
        sha3_384_list.append(soup.select_one('#sha3_hash').get_text())
        sha1_list.append(soup.select_one('#sha1_hash').get_text())
        md5_list.append(soup.select_one('#md5_hash').get_text())

        mime_type_list.append(soup.find('th', text="MIME type:").find_next_sibling('td').text)
        firstseen_list.append(soup.find('th', text="First seen:").find_next_sibling('td').text)
        file_type_list.append(soup.find('th', text="File type:").find_next_sibling('td').text)

    # Tạo DataFrame
    df = pd.DataFrame({
        'Name': names,
        'File_type': file_type_list,
        'MIME_type': mime_type_list,
        'MD5': md5_list,
        'SHA256': sha256_list,
        'SHA384': sha3_384_list,
        'SHA1': sha1_list,
        'First_seen': firstseen_list
    })

    # Đảm bảo thư mục data tồn tại
    os.makedirs(os.path.dirname(save_path), exist_ok=True)

    # Xuất CSV
    df.to_csv(save_path, index=False)
    print(f"✅ Data saved to {save_path}")


if __name__ == "__main__":
    crawl_bazaar(limit=5)  # crawl 5 mẫu thử
