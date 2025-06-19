package kotlin.io;

import java.io.File;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends a {
    public boolean b;
    public File[] c;
    public int d;
    public boolean e;
    public final /* synthetic */ e f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(e eVar, File rootDir) {
        super(rootDir);
        Intrinsics.checkNotNullParameter(rootDir, "rootDir");
        this.f = eVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x005d  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0060  */
    @Override // kotlin.io.f
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.File a() {
        /*
            r11 = this;
            boolean r0 = r11.e
            r1 = 0
            r2 = 1
            kotlin.io.e r3 = r11.f
            java.io.File r4 = r11.a
            if (r0 != 0) goto L44
            java.io.File[] r0 = r11.c
            if (r0 != 0) goto L44
            java.lang.Object r0 = r3.e
            kotlin.io.g r0 = (kotlin.io.g) r0
            kotlin.jvm.functions.Function1 r0 = r0.c
            if (r0 == 0) goto L23
            java.lang.Object r0 = r0.invoke(r4)
            java.lang.Boolean r0 = (java.lang.Boolean) r0
            boolean r0 = r0.booleanValue()
            if (r0 != 0) goto L23
            goto L6b
        L23:
            java.io.File[] r0 = r4.listFiles()
            r11.c = r0
            if (r0 != 0) goto L44
            java.lang.Object r0 = r3.e
            kotlin.io.g r0 = (kotlin.io.g) r0
            kotlin.jvm.functions.Function2 r0 = r0.e
            if (r0 == 0) goto L42
            kotlin.io.AccessDeniedException r5 = new kotlin.io.AccessDeniedException
            r7 = 0
            java.lang.String r8 = "Cannot list files in a directory"
            java.io.File r6 = r11.a
            r9 = 2
            r10 = 0
            r5.<init>(r6, r7, r8, r9, r10)
            r0.invoke(r4, r5)
        L42:
            r11.e = r2
        L44:
            java.io.File[] r0 = r11.c
            if (r0 == 0) goto L59
            int r5 = r11.d
            int r6 = r0.length
            if (r5 >= r6) goto L59
            kotlin.jvm.internal.Intrinsics.d(r0)
            int r1 = r11.d
            int r2 = r1 + 1
            r11.d = r2
            r0 = r0[r1]
            return r0
        L59:
            boolean r0 = r11.b
            if (r0 != 0) goto L60
            r11.b = r2
            return r4
        L60:
            java.lang.Object r0 = r3.e
            kotlin.io.g r0 = (kotlin.io.g) r0
            kotlin.jvm.functions.Function1 r0 = r0.d
            if (r0 == 0) goto L6b
            r0.invoke(r4)
        L6b:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlin.io.b.a():java.io.File");
    }
}
