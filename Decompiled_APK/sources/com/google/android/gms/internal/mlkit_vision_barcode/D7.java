package com.google.android.gms.internal.mlkit_vision_barcode;

/* loaded from: classes2.dex */
public enum D7 implements J {
    /* JADX INFO: Fake field, exist only in values array */
    UNRECOGNIZED(0),
    CODE_128(1),
    CODE_39(2),
    CODE_93(3),
    CODABAR(4),
    DATA_MATRIX(5),
    EAN_13(6),
    EAN_8(7),
    ITF(8),
    QR_CODE(9),
    UPC_A(10),
    UPC_E(11),
    PDF417(12),
    AZTEC(13),
    /* JADX INFO: Fake field, exist only in values array */
    DATABAR(14),
    /* JADX INFO: Fake field, exist only in values array */
    TEZ_CODE(16);

    public final int a;

    D7(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.J
    public final int zza() {
        return this.a;
    }
}
