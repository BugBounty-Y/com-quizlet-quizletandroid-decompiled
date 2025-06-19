package com.quizlet.quizletandroid.ui.setcreation.fragments;

import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ EditSetFragment b;

    public /* synthetic */ a(EditSetFragment editSetFragment, int i) {
        this.a = i;
        this.b = editSetFragment;
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x002c  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x003a A[Catch: Exception -> 0x002a, TryCatch #0 {Exception -> 0x002a, blocks: (B:7:0x000f, B:9:0x0013, B:14:0x001f, B:18:0x002d, B:20:0x003a, B:21:0x0047, B:22:0x004c, B:12:0x0019), top: B:51:0x000f }] */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0047 A[Catch: Exception -> 0x002a, TryCatch #0 {Exception -> 0x002a, blocks: (B:7:0x000f, B:9:0x0013, B:14:0x001f, B:18:0x002d, B:20:0x003a, B:21:0x0047, B:22:0x004c, B:12:0x0019), top: B:51:0x000f }] */
    @Override // kotlin.jvm.functions.Function1
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r8) {
        /*
            r7 = this;
            r0 = 0
            com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment r1 = r7.b
            int r2 = r7.a
            switch(r2) {
                case 0: goto La6;
                case 1: goto L8f;
                case 2: goto L78;
                case 3: goto L63;
                default: goto L8;
            }
        L8:
            android.net.Uri r8 = (android.net.Uri) r8
            java.lang.String r2 = com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment.J
            if (r8 == 0) goto L60
            r2 = 0
            com.quizlet.quizletandroid.ui.setcreation.adapters.f r3 = r1.A     // Catch: java.lang.Exception -> L2a
            if (r3 == 0) goto L2c
            java.util.ArrayList r3 = r3.p     // Catch: java.lang.Exception -> L2a
            if (r3 != 0) goto L19
            r3 = r2
            goto L1d
        L19:
            java.util.List r3 = java.util.Collections.unmodifiableList(r3)     // Catch: java.lang.Exception -> L2a
        L1d:
            if (r3 == 0) goto L2c
            com.quizlet.quizletandroid.ui.setcreation.managers.CardFocusPosition r4 = r1.G     // Catch: java.lang.Exception -> L2a
            int r4 = r4.a     // Catch: java.lang.Exception -> L2a
            java.lang.Object r3 = r3.get(r4)     // Catch: java.lang.Exception -> L2a
            com.quizlet.db.data.models.persisted.DBTerm r3 = (com.quizlet.db.data.models.persisted.DBTerm) r3     // Catch: java.lang.Exception -> L2a
            goto L2d
        L2a:
            r8 = move-exception
            goto L4d
        L2c:
            r3 = r2
        L2d:
            android.content.Context r4 = r1.requireContext()     // Catch: java.lang.Exception -> L2a
            java.lang.String r5 = "requireContext(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r4, r5)     // Catch: java.lang.Exception -> L2a
            com.quizlet.quizletandroid.ui.common.images.capture.c r5 = r1.u     // Catch: java.lang.Exception -> L2a
            if (r5 == 0) goto L47
            r6 = 1
            android.net.Uri r8 = com.facebook.appevents.g.c(r4, r5, r8, r6)     // Catch: java.lang.Exception -> L2a
            com.google.android.gms.internal.ads.xF r4 = r1.Y()     // Catch: java.lang.Exception -> L2a
            r4.b(r3, r8)     // Catch: java.lang.Exception -> L2a
            goto L60
        L47:
            java.lang.String r8 = "imageCache"
            kotlin.jvm.internal.Intrinsics.m(r8)     // Catch: java.lang.Exception -> L2a
            throw r2     // Catch: java.lang.Exception -> L2a
        L4d:
            com.google.android.gms.internal.ads.xF r1 = r1.Y()
            r1.f = r2
            r2 = 0
            r1.a = r2
            timber.log.a r1 = timber.log.c.a
            java.lang.Object[] r0 = new java.lang.Object[r0]
            java.lang.String r2 = "Fail to handle image on EditSetFragment"
            r1.q(r8, r2, r0)
        L60:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        L63:
            kotlin.Unit r8 = (kotlin.Unit) r8
            java.lang.String r8 = com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment.J
            com.quizlet.quizletandroid.ui.setcreation.dialogs.c r8 = new com.quizlet.quizletandroid.ui.setcreation.dialogs.c
            r8.<init>()
            androidx.fragment.app.h0 r0 = r1.getChildFragmentManager()
            java.lang.String r1 = "U13FeatureLossDialog"
            r8.O(r0, r1)
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        L78:
            kotlin.Unit r8 = (kotlin.Unit) r8
            java.lang.ref.WeakReference r8 = r1.x
            if (r8 == 0) goto L8c
            java.lang.Object r8 = r8.get()
            com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b r8 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) r8
            if (r8 != 0) goto L87
            goto L8c
        L87:
            com.quizlet.quizletandroid.ui.setcreation.activities.d r8 = (com.quizlet.quizletandroid.ui.setcreation.activities.d) r8
            r8.S()
        L8c:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        L8f:
            java.lang.Boolean r8 = (java.lang.Boolean) r8
            java.lang.String r2 = com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment.J
            com.quizlet.richtext.ui.toolbar.QRichTextToolbar r1 = r1.b0()
            boolean r8 = r8.booleanValue()
            if (r8 == 0) goto L9e
            goto La0
        L9e:
            r0 = 8
        La0:
            r1.setVisibility(r0)
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        La6:
            org.wordpress.aztec.toolbar.c r8 = (org.wordpress.aztec.toolbar.c) r8
            java.lang.String r2 = com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment.J
            if (r8 == 0) goto Lb4
            com.quizlet.richtext.ui.toolbar.QRichTextToolbar r0 = r1.b0()
            r0.a(r8)
            goto Ld0
        Lb4:
            com.quizlet.richtext.ui.toolbar.QRichTextToolbar r8 = r1.b0()
            java.util.LinkedHashSet r8 = r8.f
            java.util.Iterator r8 = r8.iterator()
        Lbe:
            boolean r1 = r8.hasNext()
            if (r1 == 0) goto Ld0
            java.lang.Object r1 = r8.next()
            com.quizlet.richtext.ui.toolbar.b r1 = (com.quizlet.richtext.ui.toolbar.b) r1
            android.widget.ToggleButton r1 = r1.a
            r1.setChecked(r0)
            goto Lbe
        Ld0:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setcreation.fragments.a.invoke(java.lang.Object):java.lang.Object");
    }
}
