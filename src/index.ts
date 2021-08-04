import {SimpleCaptchaEntity, SimpleCaptchaFactoryStorage} from '@interactiveplus/pdk2021-backend-simplecaptcha'
import { CaptchaFactoryInstallInfo } from '@interactiveplus/pdk2021-backendcore/dist/AbstractFactoryTypes/Captcha/CaptchaFactory';
import { MaskUID } from '@interactiveplus/pdk2021-common/dist/AbstractDataTypes/MaskID/MaskIDEntity';
import { UserEntityUID } from '@interactiveplus/pdk2021-common/dist/AbstractDataTypes/User/UserEntity';
import {Connection} from 'mysql2';
import { getMySQLTypeForAPPClientID, getMySQLTypeForMaskIDUID, getMySQLTypeForUserUID } from './MySQLTypeUtil';
import { fetchMySQL, fetchMySQLCount } from './MySQLFetchUtil';
import { generateRandomHexString } from '@interactiveplus/pdk2021-common/dist/Utilities/HEXString';
import { PDKItemNotFoundError, PDKUnknownInnerError } from '@interactiveplus/pdk2021-common/dist/AbstractDataTypes/Error/PDKException';
class SimpleCaptchaFactoryStorageMySQL implements SimpleCaptchaFactoryStorage{
    constructor(public mysqlConnection : Connection){

    }
    async rerollCaptchaID(captchaIDLen : number, maxCallStack?: number) : Promise<string>{
        let rolledID = generateRandomHexString(captchaIDLen);
        let loopTime = 0;
        while(maxCallStack === undefined || loopTime < maxCallStack){
            let existance = await this.checkCaptchaIDExist(rolledID);
            if(!existance){
                return rolledID;
            }else{
                rolledID = generateRandomHexString(captchaIDLen);
            }
            loopTime++;
        }
        throw new PDKUnknownInnerError('Rerolled ' + loopTime.toString() + ' times but cannot find any captcha_id that doesn\'t exist in the SimpleCaptcha Storage');
    }
    async putCaptcha(createInfo: { client_id: string | null; mask_uid?: MaskUID | undefined; uid?: UserEntityUID | undefined; ip_address: string; captcha_ans: string; issued: number; expires: number; valid: boolean }, captchaIDLen: number): Promise<SimpleCaptchaEntity> {
        let rolledCaptchaID = await this.rerollCaptchaID(captchaIDLen,10);
        let insertStatement = 
        `INSERT INTO simple_captchas (
            captcha_id,
            captcha_ans,
            client_id,
            mask_uid,
            user_uid,
            ip_addr,
            issued,
            expires,
            valid
        ) VALUES (
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?
        )`;
        await fetchMySQL(
            this.mysqlConnection,
            insertStatement,
            [
                rolledCaptchaID,
                createInfo.captcha_ans,
                createInfo.client_id,
                createInfo.mask_uid,
                createInfo.uid,
                createInfo.ip_address,
                createInfo.issued,
                createInfo.expires,
                createInfo.valid ? 1 : 0
            ],
            true
        );
        return Object.assign({captcha_id: rolledCaptchaID},createInfo);
    }
    async getCaptcha(captchaId: string): Promise<SimpleCaptchaEntity | undefined> {
        let selectStatement = 'SELECT * FROM simple_captchas WHERE captcha_id = ? LIMIT 1;';
        let selectResult = await fetchMySQL(this.mysqlConnection,selectStatement,[captchaId],true);
        if(!('length' in selectResult.result) || selectResult.result.length < 1){
            throw new PDKUnknownInnerError('Unexpected data type received when fetching data from SimpleCaptchaStorage System');
        }
        let fetchedRow : any = selectResult.result[0];
        return {
            captcha_id: fetchedRow.captcha_id,
            captcha_ans: fetchedRow.captcha_ans,
            client_id: fetchedRow.client_id,
            mask_uid: fetchedRow.mask_uid,
            uid: fetchedRow.user_uid,
            ip_address: fetchedRow.ip_addr,
            issued: fetchedRow.issued,
            expires: fetchedRow.expires,
            valid: fetchedRow.valid === 1
        };
    }
    async useCaptcha(captchaId: string): Promise<void> {
        let updateStatement = 'UPDATE simple_captchas SET valid = 0 WHERE captcha_id = ? AND valid = 0;';
        let usedResult = await fetchMySQL(this.mysqlConnection,updateStatement,[captchaId],true);
        if(!('affectedRows' in usedResult.result)){
            throw new PDKUnknownInnerError('Unexpected data type received when updating data from SimpleCaptchaStorage System');
        }
        if(usedResult.result.affectedRows < 1){
            throw new PDKItemNotFoundError(['captchaId']);
        }
        return;
    }
    async clearOutdatedAndUsedCaptchas(): Promise<void> {
        let currentTime = Math.round(Date.now() / 1000.0);
        let delStatement = 'DELETE FROM simple_captchas WHERE valid = 0 OR expires < ?';
        await fetchMySQL(this.mysqlConnection,delStatement,[currentTime],true);
    }
    async checkCaptchaIDExist(captcha_id : string) : Promise<boolean>{
        return (await fetchMySQLCount(
            this.mysqlConnection,
            'simple_captchas',
            'captcha_id = ?',
            [captcha_id],
            true            
        )) >= 1;
    }

    async install(params: CaptchaFactoryInstallInfo, captchaIDLen: number, captchaAnsLen: number): Promise<void> {
        let createTableStatement = 
        `CREATE TABLE simple_captchas
        (
            captcha_id CHAR(${captchaIDLen.toString()}) NOT NULL,
            captcha_ans CHAR(${captchaAnsLen.toString()}) NOT NULL,
            client_id ${getMySQLTypeForAPPClientID(params.appEntityFactory)},
            mask_uid ${getMySQLTypeForMaskIDUID(params.maskIDEntityFactory)},
            user_uid ${getMySQLTypeForUserUID(params.userEntityFactory)},
            ip_addr VARCHAR(45) NOT NULL,
            issued INT UNSIGNED NOT NULL,
            expires INT UNSIGNED NOT NULL,
            valid TINYINT(1) NOT NULL,
            PRIMARY KEY (captcha_id)
        );`;
        await fetchMySQL(this.mysqlConnection,createTableStatement,undefined,false);
    }
    async uninstall(): Promise<void> {
        let dropTableStatement = 'DROP TABLE simple_captchas;';
        await fetchMySQL(this.mysqlConnection,dropTableStatement,undefined,false);
    }
    async clearData(): Promise<void> {
        let clearTableStatement = 'TRUNCATE TABLE simple_captchas;';
        await fetchMySQL(this.mysqlConnection,clearTableStatement,undefined,false);
    }
}

export default SimpleCaptchaFactoryStorageMySQL;