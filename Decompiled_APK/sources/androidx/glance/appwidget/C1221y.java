package androidx.glance.appwidget;

/* renamed from: androidx.glance.appwidget.y, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1221y implements kotlin.coroutines.l {
    public static final /* synthetic */ C1221y a = new C1221y();

    public static void a(int i) {
        synchronized (UnmanagedSessionReceiver.a) {
            if (UnmanagedSessionReceiver.b.get(Integer.valueOf(i)) != null) {
                throw new ClassCastException();
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object b(android.content.Context r8, int r9, kotlin.coroutines.jvm.internal.c r10) throws java.lang.Throwable {
        /*
            r7 = this;
            boolean r0 = r10 instanceof androidx.glance.appwidget.C1181l0
            if (r0 == 0) goto L13
            r0 = r10
            androidx.glance.appwidget.l0 r0 = (androidx.glance.appwidget.C1181l0) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            androidx.glance.appwidget.l0 r0 = new androidx.glance.appwidget.l0
            r0.<init>(r7, r10)
        L18:
            java.lang.Object r10 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            java.lang.String r3 = "GlanceAppWidget"
            r4 = 1
            if (r2 == 0) goto L3b
            if (r2 != r4) goto L33
            int r9 = r0.k
            android.content.Context r8 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.io.IOException -> L2d androidx.datastore.core.CorruptionException -> L30
            goto L5d
        L2d:
            r0 = move-exception
            r10 = r0
            goto L62
        L30:
            r0 = move-exception
            r10 = r0
            goto L78
        L33:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L3b:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            androidx.glance.state.f r10 = androidx.glance.state.f.a     // Catch: java.io.IOException -> L2d androidx.datastore.core.CorruptionException -> L30
            androidx.glance.appwidget.t0 r2 = androidx.glance.appwidget.t0.a     // Catch: java.io.IOException -> L2d androidx.datastore.core.CorruptionException -> L30
            java.lang.StringBuilder r5 = new java.lang.StringBuilder     // Catch: java.io.IOException -> L2d androidx.datastore.core.CorruptionException -> L30
            java.lang.String r6 = "appWidgetLayout-"
            r5.<init>(r6)     // Catch: java.io.IOException -> L2d androidx.datastore.core.CorruptionException -> L30
            r5.append(r9)     // Catch: java.io.IOException -> L2d androidx.datastore.core.CorruptionException -> L30
            java.lang.String r5 = r5.toString()     // Catch: java.io.IOException -> L2d androidx.datastore.core.CorruptionException -> L30
            r0.j = r8     // Catch: java.io.IOException -> L2d androidx.datastore.core.CorruptionException -> L30
            r0.k = r9     // Catch: java.io.IOException -> L2d androidx.datastore.core.CorruptionException -> L30
            r0.n = r4     // Catch: java.io.IOException -> L2d androidx.datastore.core.CorruptionException -> L30
            java.lang.Object r10 = r10.c(r8, r2, r5, r0)     // Catch: java.io.IOException -> L2d androidx.datastore.core.CorruptionException -> L30
            if (r10 != r1) goto L5d
            return r1
        L5d:
            androidx.glance.appwidget.proto.e r10 = (androidx.glance.appwidget.proto.e) r10     // Catch: java.io.IOException -> L2d androidx.datastore.core.CorruptionException -> L30
        L5f:
            r1 = r8
            r4 = r9
            goto L93
        L62:
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            java.lang.String r1 = "I/O error reading set of layout structures for App Widget id "
            r0.<init>(r1)
            r0.append(r9)
            java.lang.String r0 = r0.toString()
            android.util.Log.e(r3, r0, r10)
            androidx.glance.appwidget.proto.e r10 = androidx.glance.appwidget.proto.e.n()
            goto L5f
        L78:
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            java.lang.String r1 = "Set of layout structures for App Widget id "
            r0.<init>(r1)
            r0.append(r9)
            java.lang.String r1 = " is corrupted"
            r0.append(r1)
            java.lang.String r0 = r0.toString()
            android.util.Log.e(r3, r0, r10)
            androidx.glance.appwidget.proto.e r10 = androidx.glance.appwidget.proto.e.n()
            goto L5f
        L93:
            androidx.glance.appwidget.protobuf.u r8 = r10.o()
            r9 = 10
            int r9 = kotlin.collections.C.q(r8, r9)
            int r9 = kotlin.collections.U.a(r9)
            r0 = 16
            if (r9 >= r0) goto La6
            r9 = r0
        La6:
            java.util.LinkedHashMap r0 = new java.util.LinkedHashMap
            r0.<init>(r9)
            java.util.Iterator r8 = r8.iterator()
        Laf:
            boolean r9 = r8.hasNext()
            if (r9 == 0) goto Lcc
            java.lang.Object r9 = r8.next()
            androidx.glance.appwidget.proto.g r9 = (androidx.glance.appwidget.proto.g) r9
            androidx.glance.appwidget.proto.i r2 = r9.m()
            int r9 = r9.n()
            java.lang.Integer r3 = new java.lang.Integer
            r3.<init>(r9)
            r0.put(r2, r3)
            goto Laf
        Lcc:
            java.util.LinkedHashMap r2 = kotlin.collections.V.m(r0)
            androidx.glance.appwidget.n0 r0 = new androidx.glance.appwidget.n0
            int r3 = r10.p()
            java.util.Collection r8 = r2.values()
            java.lang.Iterable r8 = (java.lang.Iterable) r8
            java.util.LinkedHashSet r5 = kotlin.collections.CollectionsKt.z0(r8)
            r0.<init>(r1, r2, r3, r4, r5)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.C1221y.b(android.content.Context, int, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
