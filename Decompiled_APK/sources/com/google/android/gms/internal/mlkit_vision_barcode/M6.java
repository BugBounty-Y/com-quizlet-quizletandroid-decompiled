package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class M6 {
    public static final long a(List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        return (list.contains(com.quizlet.generated.enums.O1.WORD) ? 2L : 0L) | (list.contains(com.quizlet.generated.enums.O1.DEFINITION) ? 4L : 0L) | (list.contains(com.quizlet.generated.enums.O1.LOCATION) ? 16L : 0L);
    }

    public static final boolean b(File srcFile, File dstFile) throws IOException {
        Intrinsics.checkNotNullParameter(srcFile, "<this>");
        Intrinsics.checkNotNullParameter(dstFile, "toFile");
        Intrinsics.checkNotNullParameter(srcFile, "srcFile");
        Intrinsics.checkNotNullParameter(dstFile, "dstFile");
        try {
            Files.move(srcFile.toPath(), dstFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            return true;
        } catch (IOException unused) {
            return false;
        }
    }

    public static final ArrayList c(boolean z, boolean z2, boolean z3) {
        ArrayList arrayList = new ArrayList(3);
        if (z) {
            arrayList.add(com.quizlet.generated.enums.O1.WORD);
        }
        if (z2) {
            arrayList.add(com.quizlet.generated.enums.O1.DEFINITION);
        }
        if (z3) {
            arrayList.add(com.quizlet.generated.enums.O1.LOCATION);
        }
        return arrayList;
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x004b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.util.ArrayList d(long r9) {
        /*
            com.quizlet.generated.enums.O1[] r0 = com.quizlet.generated.enums.O1.values()
            java.util.ArrayList r1 = new java.util.ArrayList
            r1.<init>()
            int r2 = r0.length
            r3 = 0
        Lb:
            if (r3 >= r2) goto L51
            r4 = r0[r3]
            java.lang.String r5 = "termSide"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r5)
            int[] r5 = com.quizlet.features.infra.studysetting.util.a.a
            int r6 = r4.ordinal()
            r5 = r5[r6]
            r6 = 1
            r7 = 0
            if (r5 == r6) goto L44
            r6 = 2
            if (r5 == r6) goto L3c
            r6 = 3
            if (r5 == r6) goto L34
            r4 = 4
            if (r5 == r4) goto L4e
            r4 = 5
            if (r5 != r4) goto L2e
            goto L4e
        L2e:
            kotlin.NoWhenBranchMatchedException r9 = new kotlin.NoWhenBranchMatchedException
            r9.<init>()
            throw r9
        L34:
            r5 = 16
            long r5 = r5 & r9
            int r5 = (r5 > r7 ? 1 : (r5 == r7 ? 0 : -1))
            if (r5 == 0) goto L4e
            goto L4b
        L3c:
            r5 = 4
            long r5 = r5 & r9
            int r5 = (r5 > r7 ? 1 : (r5 == r7 ? 0 : -1))
            if (r5 == 0) goto L4e
            goto L4b
        L44:
            r5 = 2
            long r5 = r5 & r9
            int r5 = (r5 > r7 ? 1 : (r5 == r7 ? 0 : -1))
            if (r5 == 0) goto L4e
        L4b:
            r1.add(r4)
        L4e:
            int r3 = r3 + 1
            goto Lb
        L51:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.M6.d(long):java.util.ArrayList");
    }

    public static boolean e(Context context) {
        ((com.quizlet.quizletandroid.u) ((dagger.hilt.android.flags.a) L6.b(context, dagger.hilt.android.flags.a.class))).getClass();
        int i = com.google.common.collect.o.c;
        com.google.common.collect.D d = com.google.common.collect.D.j;
        R6.b(d.h <= 1, "Cannot bind the flag @DisableFragmentGetContextFix more than once.", new Object[0]);
        if (d.isEmpty()) {
            return true;
        }
        return ((Boolean) d.iterator().next()).booleanValue();
    }
}
