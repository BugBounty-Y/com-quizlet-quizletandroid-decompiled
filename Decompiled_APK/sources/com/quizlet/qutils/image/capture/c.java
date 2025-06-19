package com.quizlet.qutils.image.capture;

import android.graphics.Bitmap;
import java.io.File;
import java.util.Set;
import kotlin.collections.C4933y;
import kotlin.io.k;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;

/* loaded from: classes3.dex */
public abstract class c {
    public static final Set a;

    static {
        String[] elements = {"JPG", "JPEG", "DNG", "CR2", "NEF", "NRW", "ARW", "RW2", "ORF", "PEF", "SRW", "RAF"};
        Intrinsics.checkNotNullParameter(elements, "elements");
        a = C4933y.T(elements);
    }

    public static final Bitmap.CompressFormat a(File file) {
        Intrinsics.checkNotNullParameter(file, "<this>");
        Intrinsics.checkNotNullParameter(file, "<this>");
        if (D.l(k.f(file), "JPG", true) || D.l(k.f(file), "JPEG", true)) {
            return Bitmap.CompressFormat.JPEG;
        }
        Intrinsics.checkNotNullParameter(file, "<this>");
        if (D.l(k.f(file), "PNG", true)) {
            return Bitmap.CompressFormat.PNG;
        }
        Intrinsics.checkNotNullParameter(file, "<this>");
        return D.l(k.f(file), "WEBP", true) ? Bitmap.CompressFormat.WEBP : Bitmap.CompressFormat.JPEG;
    }
}
