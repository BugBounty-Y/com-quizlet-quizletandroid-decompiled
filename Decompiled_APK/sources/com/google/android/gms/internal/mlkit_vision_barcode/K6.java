package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import androidx.camera.camera2.internal.AbstractC0147y;
import java.io.File;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class K6 {
    public static final File a(Context context, String fileName) {
        Intrinsics.checkNotNullParameter(context, "<this>");
        Intrinsics.checkNotNullParameter(fileName, "fileName");
        return new File(context.getApplicationContext().getFilesDir(), AbstractC0147y.d("datastore/", fileName));
    }

    public static Object b(Class cls, Object obj) {
        if (obj instanceof dagger.hilt.internal.a) {
            return cls.cast(obj);
        }
        if (obj instanceof dagger.hilt.internal.b) {
            return b(cls, ((dagger.hilt.internal.b) obj).d());
        }
        throw new IllegalStateException("Given component holder " + obj.getClass() + " does not implement " + dagger.hilt.internal.a.class + " or " + dagger.hilt.internal.b.class);
    }

    public static final assistantMode.enums.w c(com.quizlet.studiablemodels.assistantMode.a aVar) {
        Intrinsics.checkNotNullParameter(aVar, "<this>");
        int iOrdinal = aVar.ordinal();
        if (iOrdinal == 0) {
            return assistantMode.enums.w.d;
        }
        if (iOrdinal == 1) {
            return assistantMode.enums.w.c;
        }
        if (iOrdinal == 2) {
            return assistantMode.enums.w.d;
        }
        if (iOrdinal == 3) {
            return assistantMode.enums.w.e;
        }
        throw new NoWhenBranchMatchedException();
    }
}
