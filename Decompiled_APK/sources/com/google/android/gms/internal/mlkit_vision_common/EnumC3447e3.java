package com.google.android.gms.internal.mlkit_vision_common;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.e3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public enum EnumC3447e3 implements InterfaceC3425b {
    /* JADX INFO: Fake field, exist only in values array */
    SOURCE_UNKNOWN(0),
    /* JADX INFO: Fake field, exist only in values array */
    BITMAP(1),
    /* JADX INFO: Fake field, exist only in values array */
    BYTEARRAY(2),
    /* JADX INFO: Fake field, exist only in values array */
    BYTEBUFFER(3),
    /* JADX INFO: Fake field, exist only in values array */
    FILEPATH(4),
    ANDROID_MEDIA_IMAGE(5);

    public final int a;

    EnumC3447e3(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.InterfaceC3425b
    public final int zza() {
        return this.a;
    }
}
