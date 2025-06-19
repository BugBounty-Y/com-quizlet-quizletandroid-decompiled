package com.google.android.gms.internal.mlkit_vision_camera;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.s1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public enum EnumC3389s1 implements C0 {
    /* JADX INFO: Fake field, exist only in values array */
    EVENT_TYPE_UNKNOWN(0),
    EVENT_TYPE_CREATE(1),
    EVENT_TYPE_START(2),
    EVENT_TYPE_STOP(3),
    EVENT_TYPE_CLOSE(4),
    EVENT_TYPE_START_WITH_PREVIEW(5);

    public final int a;

    EnumC3389s1(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.C0
    public final int zza() {
        return this.a;
    }
}
