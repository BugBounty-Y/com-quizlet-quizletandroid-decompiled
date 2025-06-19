package com.google.android.gms.internal.mlkit_vision_barcode;

import android.opengl.Matrix;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class Q {
    public static final /* synthetic */ int a = 0;

    public static final String a(okhttp3.r rVar) {
        Intrinsics.checkNotNullParameter(rVar, "<this>");
        Intrinsics.checkNotNullParameter("Search-Session-Id", "name");
        String strA = rVar.a("Search-Session-Id");
        return strA == null ? "" : strA;
    }

    public static void b(float f, float[] fArr) {
        Matrix.translateM(fArr, 0, 0.5f, 0.5f, DefinitionKt.NO_Float_VALUE);
        Matrix.rotateM(fArr, 0, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 1.0f);
        Matrix.translateM(fArr, 0, -0.5f, -0.5f, DefinitionKt.NO_Float_VALUE);
    }

    public static void c(float[] fArr) {
        Matrix.translateM(fArr, 0, DefinitionKt.NO_Float_VALUE, 0.5f, DefinitionKt.NO_Float_VALUE);
        Matrix.scaleM(fArr, 0, 1.0f, -1.0f, 1.0f);
        Matrix.translateM(fArr, 0, -0.0f, -0.5f, DefinitionKt.NO_Float_VALUE);
    }
}
