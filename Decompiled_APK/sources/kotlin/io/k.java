package kotlin.io;

import java.io.File;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public class k extends j {
    public static boolean e(File file) {
        Intrinsics.checkNotNullParameter(file, "<this>");
        Intrinsics.checkNotNullParameter(file, "<this>");
        e eVar = new e(j.d(file, FileWalkDirection.b));
        while (true) {
            boolean z = true;
            while (eVar.hasNext()) {
                File file2 = (File) eVar.next();
                if (!file2.delete() && file2.exists()) {
                    z = false;
                } else {
                    if (z) {
                        break;
                    }
                    z = false;
                }
            }
            return z;
        }
    }

    public static String f(File file) {
        Intrinsics.checkNotNullParameter(file, "<this>");
        String name = file.getName();
        Intrinsics.checkNotNullExpressionValue(name, "getName(...)");
        return StringsKt.c0(name, "", '.');
    }
}
