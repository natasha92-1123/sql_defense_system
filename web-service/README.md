## 環境需求

- Docker (推薦: v5.1.4) 
- Docker Compose（推薦: 29.5.2, build 79eb04c）

## 執行方式

於本專案 web-service 目錄下

執行以下指令

```bash!
docker compose up -d
```

若需要關閉服務器

```!
docker compose down
```

## Lab 列表:

* [Lab1: CVE-2017-8917](https://github.com/vulhub/vulhub/blob/master/joomla/CVE-2017-8917/README.zh-cn.md)
	* 環境: Joomla 3.7.0
	* 漏洞簡述: 內建的 `com_fields` 組件中存在 SQL 注入漏洞。遠端攻擊者無需任何權限，即可透過特定的 URL 參數注入惡意 SQL 指令，進而讀取資料庫敏感資訊。
    * 預設帳密: admin/admin
* [Lab2: CVE-2024-31025, CVE-2021-41460](https://github.com/vulhub/vulhub/blob/master/ecshop/collection_list-sqli/README.zh-cn.md)
	* 環境: ECShop 4.0.6
	* 漏洞簡述: 由於對傳入的參數缺乏安全過濾，導致攻擊者可構造惡意 Payload 進行 SQL 注入攻擊。
    * 需要自己初始化
* [Lab3: CVE-2019-8114](https://github.com/vulhub/vulhub/blob/master/magento/2.2-sqli/README.zh-cn.md)
	* 環境: Magento 2.2.7
	* 漏洞簡述: 存在反序列化與遠端代碼執行（RCE）漏洞。攻擊者可以結合特定的佈局（Layout）更新或 SQL 注入獲取的高階權限，構造惡意序列化資料，在系統解析時觸發任意系統指令執行。
     * 需要自己初始化
* [Lab4: xianzhi-2017-02-82239600](https://github.com/vulhub/vulhub/blob/master/ecshop/xianzhi-2017-02-82239600/README.zh-cn.md)
	* 環境: ECShop 3.6.0
	* 漏洞簡述: 在 `user.php` 中，若 `HTTP_REFERER` 傳入的惡意字串帶入 SQL 查詢並寫入 Session 後，會被後台的 Smarty 模板引擎不當解析，導致未登入的攻擊者可直接執行任意 PHP 代碼。
    * 需要自己初始化
* [Lab5: CVE-2014-3704](https://github.com/vulhub/vulhub/blob/master/drupal/CVE-2014-3704/README.zh-cn.md)
	* 環境: Drupal 7.31
	* 漏洞簡述: 著名的 "Drupalgeddon" 漏洞。核心資料庫抽象層（Database API）在擴展帶有陣列（Array）的 SQL 語句時未正確進行安全過濾，未授權攻擊者可透過特製的 POST 請求直接執行任意 SQL 指令，進而控制整個網站或執行系統代碼。
    * 需要自己初始化，如果要透過 https 訪問，需要修改 `/var/www/html/sites/default/settings.php`，設置 `$base_url` 為自己的網域。
* [Lab6: CVE-2024-27956](https://github.com/truonghuuphuc/CVE-2024-27956/tree/main)
	* 環境: WordPress (WP-Automatic 插件漏洞環境)
	* 漏洞簡述: 存在於 WordPress 熱門插件 `WP-Automatic`（3.92.0 及以下版本）中的 SQL 注入漏洞。由於插件未對使用者輸入進行有效的過濾與參數化查詢，未授權的遠端攻擊者可直接執行惡意 SQL 指令、建立偽造的管理員帳號或竊取資料庫內容。