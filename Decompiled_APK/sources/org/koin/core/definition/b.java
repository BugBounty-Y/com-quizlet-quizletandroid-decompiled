package org.koin.core.definition;

import kotlin.collections.K;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final org.koin.core.qualifier.a a;
    public final C4950i b;
    public final org.koin.core.qualifier.a c;
    public final Function2 d;
    public final c e;
    public Object f;

    public b(org.koin.core.qualifier.a scopeQualifier, C4950i primaryType, org.koin.core.qualifier.a aVar, Function2 definition, c kind, K secondaryTypes) {
        Intrinsics.checkNotNullParameter(scopeQualifier, "scopeQualifier");
        Intrinsics.checkNotNullParameter(primaryType, "primaryType");
        Intrinsics.checkNotNullParameter(definition, "definition");
        Intrinsics.checkNotNullParameter(kind, "kind");
        Intrinsics.checkNotNullParameter(secondaryTypes, "secondaryTypes");
        this.a = scopeQualifier;
        this.b = primaryType;
        this.c = aVar;
        this.d = definition;
        this.e = kind;
        this.f = secondaryTypes;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        Intrinsics.e(obj, "null cannot be cast to non-null type org.koin.core.definition.BeanDefinition<*>");
        b bVar = (b) obj;
        return this.b.equals(bVar.b) && Intrinsics.b(this.c, bVar.c) && Intrinsics.b(this.a, bVar.a);
    }

    public final int hashCode() {
        org.koin.core.qualifier.a aVar = this.c;
        return this.a.a.hashCode() + ((this.b.hashCode() + ((aVar != null ? aVar.a.hashCode() : 0) * 31)) * 31);
    }

    /* JADX WARN: Removed duplicated region for block: B:6:0x0035  */
    /* JADX WARN: Type inference failed for: r5v1, types: [java.lang.Object, java.util.Collection] */
    /* JADX WARN: Type inference failed for: r6v2, types: [java.lang.Iterable, java.lang.Object] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String toString() {
        /*
            r12 = this;
            org.koin.core.definition.c r0 = r12.e
            java.lang.String r0 = r0.toString()
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            java.lang.String r2 = "'"
            r1.<init>(r2)
            kotlin.jvm.internal.i r2 = r12.b
            java.lang.String r2 = org.koin.ext.a.a(r2)
            r1.append(r2)
            r2 = 39
            r1.append(r2)
            java.lang.String r1 = r1.toString()
            org.koin.core.qualifier.a r2 = r12.c
            java.lang.String r3 = ""
            if (r2 == 0) goto L35
            java.lang.StringBuilder r4 = new java.lang.StringBuilder
            java.lang.String r5 = ",qualifier:"
            r4.<init>(r5)
            r4.append(r2)
            java.lang.String r2 = r4.toString()
            if (r2 != 0) goto L36
        L35:
            r2 = r3
        L36:
            org.koin.core.qualifier.a r4 = org.koin.core.registry.a.c
            org.koin.core.qualifier.a r5 = r12.a
            boolean r4 = kotlin.jvm.internal.Intrinsics.b(r5, r4)
            if (r4 == 0) goto L42
            r4 = r3
            goto L50
        L42:
            java.lang.StringBuilder r4 = new java.lang.StringBuilder
            java.lang.String r6 = ",scope:"
            r4.<init>(r6)
            r4.append(r5)
            java.lang.String r4 = r4.toString()
        L50:
            java.lang.Object r5 = r12.f
            boolean r5 = r5.isEmpty()
            if (r5 != 0) goto L6c
            java.lang.Object r6 = r12.f
            org.koin.core.definition.a r10 = org.koin.core.definition.a.a
            r8 = 0
            r9 = 0
            java.lang.String r7 = ","
            r11 = 30
            java.lang.String r3 = kotlin.collections.CollectionsKt.S(r6, r7, r8, r9, r10, r11)
            java.lang.String r5 = ",binds:"
            java.lang.String r3 = androidx.camera.camera2.internal.AbstractC0147y.d(r5, r3)
        L6c:
            java.lang.StringBuilder r5 = new java.lang.StringBuilder
            java.lang.String r6 = "["
            r5.<init>(r6)
            r5.append(r0)
            r0 = 58
            r5.append(r0)
            r5.append(r1)
            r5.append(r2)
            r5.append(r4)
            r5.append(r3)
            r0 = 93
            r5.append(r0)
            java.lang.String r0 = r5.toString()
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: org.koin.core.definition.b.toString():java.lang.String");
    }
}
