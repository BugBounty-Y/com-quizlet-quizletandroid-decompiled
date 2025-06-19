package org.koin.core.scope;

import com.quizlet.quizletandroid.ui.joincontenttofolder.j;
import java.util.ArrayList;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import org.koin.core.error.ClosedScopeException;
import org.koin.core.error.NoBeanDefFoundException;

/* loaded from: classes3.dex */
public final class a {
    public final org.koin.core.qualifier.a a;
    public final com.quizlet.data.repository.login.a b;
    public final ArrayList c;
    public final ThreadLocal d;

    public a(org.koin.core.qualifier.a scopeQualifier, com.quizlet.data.repository.login.a _koin) {
        Intrinsics.checkNotNullParameter(scopeQualifier, "scopeQualifier");
        Intrinsics.checkNotNullParameter("_root_", "id");
        Intrinsics.checkNotNullParameter(_koin, "_koin");
        this.a = scopeQualifier;
        this.b = _koin;
        this.c = new ArrayList();
        new ArrayList();
        this.d = new ThreadLocal();
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x002a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.jvm.functions.Function0 r10, kotlin.jvm.internal.C4950i r11, org.koin.core.qualifier.a r12) throws org.koin.core.error.NoBeanDefFoundException {
        /*
            r9 = this;
            java.lang.String r0 = "clazz"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r11, r0)
            com.quizlet.data.repository.login.a r0 = r9.b
            java.lang.Object r1 = r0.c
            com.quizlet.quizletandroid.ui.joincontenttofolder.j r1 = (com.quizlet.quizletandroid.ui.joincontenttofolder.j) r1
            org.koin.core.logger.a r2 = org.koin.core.logger.a.a
            boolean r1 = r1.f(r2)
            if (r1 == 0) goto L8f
            r1 = 39
            if (r12 == 0) goto L2a
            java.lang.StringBuilder r3 = new java.lang.StringBuilder
            java.lang.String r4 = " with qualifier '"
            r3.<init>(r4)
            r3.append(r12)
            r3.append(r1)
            java.lang.String r3 = r3.toString()
            if (r3 != 0) goto L2c
        L2a:
            java.lang.String r3 = ""
        L2c:
            java.lang.Object r4 = r0.c
            com.quizlet.quizletandroid.ui.joincontenttofolder.j r4 = (com.quizlet.quizletandroid.ui.joincontenttofolder.j) r4
            java.lang.StringBuilder r5 = new java.lang.StringBuilder
            java.lang.String r6 = "|- '"
            r5.<init>(r6)
            java.lang.String r7 = org.koin.ext.a.a(r11)
            r5.append(r7)
            r5.append(r1)
            r5.append(r3)
            java.lang.String r1 = " ..."
            r5.append(r1)
            java.lang.String r1 = r5.toString()
            r4.getClass()
            com.quizlet.quizletandroid.ui.joincontenttofolder.j.b(r2, r1)
            long r3 = java.lang.System.nanoTime()
            java.lang.Object r10 = r9.c(r10, r11, r12)
            long r7 = java.lang.System.nanoTime()
            long r7 = r7 - r3
            double r3 = (double) r7
            r7 = 4696837146684686336(0x412e848000000000, double:1000000.0)
            double r3 = r3 / r7
            java.lang.Object r12 = r0.c
            com.quizlet.quizletandroid.ui.joincontenttofolder.j r12 = (com.quizlet.quizletandroid.ui.joincontenttofolder.j) r12
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>(r6)
            java.lang.String r11 = org.koin.ext.a.a(r11)
            r0.append(r11)
            java.lang.String r11 = "' in "
            r0.append(r11)
            r0.append(r3)
            java.lang.String r11 = " ms"
            r0.append(r11)
            java.lang.String r11 = r0.toString()
            r12.getClass()
            com.quizlet.quizletandroid.ui.joincontenttofolder.j.b(r2, r11)
            return r10
        L8f:
            java.lang.Object r10 = r9.c(r10, r11, r12)
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: org.koin.core.scope.a.a(kotlin.jvm.functions.Function0, kotlin.jvm.internal.i, org.koin.core.qualifier.a):java.lang.Object");
    }

    public final Object b(Function0 function0, C4950i clazz, org.koin.core.qualifier.a aVar) {
        com.quizlet.data.repository.login.a aVar2 = this.b;
        Intrinsics.checkNotNullParameter(clazz, "clazz");
        try {
            return a(function0, clazz, aVar);
        } catch (ClosedScopeException unused) {
            ((j) aVar2.c).a("* Scope closed - no instance found for " + org.koin.ext.a.a(clazz) + " on scope " + this);
            return null;
        } catch (NoBeanDefFoundException unused2) {
            ((j) aVar2.c).a("* No instance found for type '" + org.koin.ext.a.a(clazz) + "' on scope '" + this + '\'');
            return null;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x00da  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x0180  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(kotlin.jvm.functions.Function0 r19, kotlin.jvm.internal.C4950i r20, org.koin.core.qualifier.a r21) throws org.koin.core.error.NoBeanDefFoundException {
        /*
            Method dump skipped, instructions count: 446
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: org.koin.core.scope.a.c(kotlin.jvm.functions.Function0, kotlin.jvm.internal.i, org.koin.core.qualifier.a):java.lang.Object");
    }

    public final String toString() {
        return "['_root_']";
    }
}
