package com.google.android.gms.internal.mlkit_vision_barcode;

/* loaded from: classes2.dex */
public final /* synthetic */ class K7 implements com.google.firebase.inject.b {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.google.android.datatransport.runtime.o b;

    public /* synthetic */ K7(com.google.android.datatransport.runtime.o oVar, int i) {
        this.a = i;
        this.b = oVar;
    }

    @Override // com.google.firebase.inject.b
    public final Object get() {
        switch (this.a) {
            case 0:
                return this.b.a("FIREBASE_ML_SDK", new com.google.android.datatransport.c("json"), new N7(3));
            case 1:
                return this.b.a("FIREBASE_ML_SDK", new com.google.android.datatransport.c("proto"), new N7(2));
            case 2:
                return this.b.a("FIREBASE_ML_SDK", new com.google.android.datatransport.c("json"), com.google.android.gms.internal.mlkit_vision_camera.i3.d);
            case 3:
                return this.b.a("FIREBASE_ML_SDK", new com.google.android.datatransport.c("proto"), com.google.android.gms.internal.mlkit_vision_camera.i3.e);
            case 4:
                return this.b.a("FIREBASE_ML_SDK", new com.google.android.datatransport.c("json"), com.google.android.gms.internal.mlkit_vision_common.O4.e);
            case 5:
                return this.b.a("FIREBASE_ML_SDK", new com.google.android.datatransport.c("proto"), com.google.android.gms.internal.mlkit_vision_common.O4.d);
            case 6:
                return this.b.a("FIREBASE_ML_SDK", new com.google.android.datatransport.c("json"), com.google.android.gms.internal.mlkit_vision_document_scanner.s7.e);
            default:
                return this.b.a("FIREBASE_ML_SDK", new com.google.android.datatransport.c("proto"), com.google.android.gms.internal.mlkit_vision_document_scanner.s7.d);
        }
    }
}
