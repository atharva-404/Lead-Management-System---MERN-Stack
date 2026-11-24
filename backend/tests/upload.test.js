const { describe, it } = require('node:test');
const assert = require('node:assert');

const validateFileType = (ext) => {
    const allowed = ['.csv', '.xlsx', '.xls'];
    return allowed.includes(ext);
};

describe('File Type Validation', () => {
    it('should accept valid CSV file', () => {
        assert.strictEqual(validateFileType('.csv'), true);
    });
    it('should accept valid XLSX file', () => {
        assert.strictEqual(validateFileType('.xlsx'), true);
    });
    it('should accept valid XLS file', () => {
        assert.strictEqual(validateFileType('.xls'), true);
    });
    it('should reject invalid file type', () => {
        assert.strictEqual(validateFileType('.txt'), false);
        assert.strictEqual(validateFileType('.pdf'), false);
    });
});