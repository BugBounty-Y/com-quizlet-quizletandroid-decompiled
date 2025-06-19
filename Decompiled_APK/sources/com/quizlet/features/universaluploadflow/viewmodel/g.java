package com.quizlet.features.universaluploadflow.viewmodel;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import androidx.work.impl.model.l;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4;
import com.quizlet.data.model.m2;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import com.quizlet.eventlogger.model.UniversalUploadFlowEventLog;
import com.quizlet.features.universaluploadflow.data.C;
import com.quizlet.features.universaluploadflow.data.C4457f;
import com.quizlet.features.universaluploadflow.data.C4459h;
import com.quizlet.features.universaluploadflow.data.C4460i;
import com.quizlet.features.universaluploadflow.data.C4461j;
import com.quizlet.features.universaluploadflow.data.C4462k;
import com.quizlet.features.universaluploadflow.data.C4463l;
import com.quizlet.features.universaluploadflow.data.D;
import com.quizlet.features.universaluploadflow.data.H;
import com.quizlet.features.universaluploadflow.data.I;
import com.quizlet.features.universaluploadflow.data.InterfaceC4456e;
import com.quizlet.features.universaluploadflow.data.J;
import com.quizlet.features.universaluploadflow.data.L;
import com.quizlet.features.universaluploadflow.data.n;
import com.quizlet.features.universaluploadflow.data.o;
import com.quizlet.features.universaluploadflow.data.p;
import com.quizlet.features.universaluploadflow.data.q;
import com.quizlet.features.universaluploadflow.data.r;
import com.quizlet.features.universaluploadflow.data.s;
import com.quizlet.features.universaluploadflow.data.t;
import com.quizlet.features.universaluploadflow.data.u;
import com.quizlet.features.universaluploadflow.data.v;
import com.quizlet.features.universaluploadflow.data.w;
import com.quizlet.features.universaluploadflow.data.x;
import com.quizlet.features.universaluploadflow.data.y;
import com.quizlet.features.universaluploadflow.data.z;
import com.quizlet.generated.enums.EnumC4471c0;
import com.quizlet.generated.enums.EnumC4483g0;
import com.quizlet.generated.enums.EnumC4503n;
import com.quizlet.ui.models.webpage.m;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class g extends w0 implements a {
    public final m0 b;
    public final com.google.android.gms.internal.appset.e c;
    public final l d;
    public final com.quizlet.features.universaluploadflow.logging.b e;
    public final com.quizlet.data.repository.set.f f;
    public final UserInfoCache g;
    public final androidx.work.impl.model.e h;
    public final m2 i;
    public final s0 j;
    public final d0 k;
    public final C4203d l;

    public g(m0 savedStateHandle, com.google.android.gms.internal.appset.e uploadContentUseCase, l getUploadsEntitlementUseCase, com.quizlet.features.universaluploadflow.logging.b eventLogger, com.quizlet.data.repository.set.f fileHelper, UserInfoCache userInfoCache, androidx.work.impl.model.e practiceTestUploadEligibilityFeature) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(uploadContentUseCase, "uploadContentUseCase");
        Intrinsics.checkNotNullParameter(getUploadsEntitlementUseCase, "getUploadsEntitlementUseCase");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(fileHelper, "fileHelper");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(practiceTestUploadEligibilityFeature, "practiceTestUploadEligibilityFeature");
        this.b = savedStateHandle;
        this.c = uploadContentUseCase;
        this.d = getUploadsEntitlementUseCase;
        this.e = eventLogger;
        this.f = fileHelper;
        this.g = userInfoCache;
        this.h = practiceTestUploadEligibilityFeature;
        Object objA = savedStateHandle.a("source");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.i = (m2) objA;
        this.j = e0.c(J.a);
        this.k = e0.b(0, 1, null, 5);
        this.l = new C4203d(this);
        E.A(p0.j(this), null, null, new d(this, null), 3);
    }

    /* JADX WARN: Code restructure failed: missing block: B:27:0x0082, code lost:
    
        if (r5.E(r0) == r1) goto L28;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.features.universaluploadflow.viewmodel.g r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5.getClass()
            boolean r0 = r6 instanceof com.quizlet.features.universaluploadflow.viewmodel.b
            if (r0 == 0) goto L16
            r0 = r6
            com.quizlet.features.universaluploadflow.viewmodel.b r0 = (com.quizlet.features.universaluploadflow.viewmodel.b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.features.universaluploadflow.viewmodel.b r0 = new com.quizlet.features.universaluploadflow.viewmodel.b
            r0.<init>(r5, r6)
        L1b:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3b
            if (r2 == r4) goto L35
            if (r2 != r3) goto L2d
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L85
        L2d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L35:
            com.quizlet.features.universaluploadflow.viewmodel.g r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4b
        L3b:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r5
            r0.m = r4
            androidx.work.impl.model.e r6 = r5.h
            java.lang.Object r6 = r6.l(r0)
            if (r6 != r1) goto L4b
            goto L84
        L4b:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            com.quizlet.db.data.caches.UserInfoCache r2 = r5.g
            boolean r2 = r2.b()
            if (r2 == 0) goto L79
            if (r6 != 0) goto L79
        L5b:
            kotlinx.coroutines.flow.s0 r6 = r5.j
            java.lang.Object r0 = r6.getValue()
            r1 = r0
            com.quizlet.features.universaluploadflow.data.K r1 = (com.quizlet.features.universaluploadflow.data.K) r1
            com.quizlet.features.universaluploadflow.data.H r1 = new com.quizlet.features.universaluploadflow.data.H
            com.quizlet.features.universaluploadflow.data.d r2 = new com.quizlet.features.universaluploadflow.data.d
            com.quizlet.data.model.m2 r3 = r5.i
            r2.<init>(r3)
            r1.<init>(r2)
            boolean r6 = r6.k(r0, r1)
            if (r6 == 0) goto L5b
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L79:
            r6 = 0
            r0.j = r6
            r0.m = r3
            java.lang.Object r5 = r5.E(r0)
            if (r5 != r1) goto L85
        L84:
            return r1
        L85:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.universaluploadflow.viewmodel.g.A(com.quizlet.features.universaluploadflow.viewmodel.g, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final void B(g gVar, InterfaceC4456e interfaceC4456e) {
        s0 s0Var;
        Object value;
        gVar.e.h();
        do {
            s0Var = gVar.j;
            value = s0Var.getValue();
        } while (!s0Var.k(value, new H(interfaceC4456e)));
    }

    public final boolean C() {
        Boolean bool = (Boolean) this.b.a("isPrivacySettingsPublic");
        if (bool != null) {
            return bool.booleanValue();
        }
        return true;
    }

    public final void D(r event) {
        s0 s0Var;
        Object value;
        m mVar;
        String tabName;
        String strA;
        UniversalUploadFlowEventLog.Companion companion;
        EnumC4503n enumC4503nD;
        int iOrdinal;
        Intrinsics.checkNotNullParameter(event, "event");
        boolean zB = Intrinsics.b(event, C4460i.a);
        d0 d0Var = this.k;
        if (zB) {
            d0Var.h(v.a);
            return;
        }
        boolean z = event instanceof o;
        m2 m2Var = this.i;
        com.quizlet.features.universaluploadflow.logging.b bVar = this.e;
        if (!z) {
            if (event instanceof C4462k) {
                u uVar = ((C4462k) event).a;
                if (Intrinsics.b(uVar, s.a)) {
                    mVar = com.quizlet.ui.models.webpage.d.c;
                } else {
                    if (!Intrinsics.b(uVar, t.a)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    mVar = com.quizlet.ui.models.webpage.a.c;
                }
                d0Var.h(new com.quizlet.features.universaluploadflow.data.E(mVar));
                return;
            }
            if (event instanceof com.quizlet.features.universaluploadflow.data.m) {
                this.b.c(Boolean.valueOf(((com.quizlet.features.universaluploadflow.data.m) event).a), "isPrivacySettingsPublic");
                return;
            }
            if (!(event instanceof C4461j)) {
                if (Intrinsics.b(event, p.a)) {
                    bVar.g();
                    E.A(p0.j(this), null, null, new d(this, null), 3);
                    return;
                } else if (Intrinsics.b(event, C4463l.a)) {
                    d0Var.h(new y(m2Var));
                    return;
                } else if (Intrinsics.b(event, n.a)) {
                    d0Var.h(new C(m2Var));
                    return;
                } else {
                    if (!(event instanceof q)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    d0Var.h(new com.quizlet.features.universaluploadflow.data.E(((q) event).a));
                    return;
                }
            }
            ArrayList arrayList = ((C4461j) event).a;
            bVar.f();
            ArrayList arrayList2 = new ArrayList();
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                String strH = this.f.h((String) it2.next());
                if (strH != null) {
                    arrayList2.add(strH);
                }
            }
            com.quizlet.features.universaluploadflow.logging.b.d(this.e, C(), EnumC4483g0.FILE.a(), null, arrayList2, 4);
            do {
                s0Var = this.j;
                value = s0Var.getValue();
            } while (!s0Var.k(value, new I(m2Var)));
            E.A(p0.j(this), this.l, null, new e(arrayList, this, arrayList2, null), 2);
            return;
        }
        L l = ((o) event).a;
        if (!this.g.b()) {
            d0Var.h(D.a);
            return;
        }
        Intrinsics.checkNotNullParameter(l, "<this>");
        int iOrdinal2 = l.ordinal();
        if (iOrdinal2 == 0) {
            tabName = "paste_text";
        } else if (iOrdinal2 == 1) {
            tabName = "photo_library";
        } else if (iOrdinal2 == 2) {
            tabName = "upload_file";
        } else {
            if (iOrdinal2 != 3) {
                throw new NoWhenBranchMatchedException();
            }
            tabName = "flashcard_sets";
        }
        m2 m2Var2 = bVar.b;
        Intrinsics.checkNotNullParameter(tabName, "tabName");
        try {
            companion = UniversalUploadFlowEventLog.b;
            enumC4503nD = AbstractC3442d4.d(m2Var2);
            Intrinsics.checkNotNullParameter(m2Var2, "<this>");
            iOrdinal = m2Var2.ordinal();
        } catch (IllegalStateException unused) {
        }
        if (iOrdinal == 0 || iOrdinal == 1) {
            throw new IllegalStateException("Upload page tab changed is not applicable for this source");
        }
        if (iOrdinal != 2) {
            throw new NoWhenBranchMatchedException();
        }
        com.quizlet.features.notes.logging.c cVar = new com.quizlet.features.notes.logging.c(tabName, 26);
        companion.getClass();
        bVar.a(UniversalUploadFlowEventLog.Companion.a(enumC4503nD, "upload_page_tab_changed", cVar));
        int iOrdinal3 = l.ordinal();
        if (iOrdinal3 == 0) {
            d0Var.h(new z(new C4459h(C(), m2Var)));
            return;
        }
        if (iOrdinal3 != 1) {
            if (iOrdinal3 != 2) {
                if (iOrdinal3 != 3) {
                    throw new NoWhenBranchMatchedException();
                }
                d0Var.h(new x(new C4457f(C(), m2Var)));
                return;
            }
            UniversalUploadFlowEventLog.Companion companion2 = UniversalUploadFlowEventLog.b;
            m2 m2Var3 = bVar.b;
            EnumC4503n enumC4503nD2 = AbstractC3442d4.d(m2Var3);
            Intrinsics.checkNotNullParameter(m2Var3, "<this>");
            int iOrdinal4 = m2Var3.ordinal();
            if (iOrdinal4 == 0 || iOrdinal4 == 1) {
                strA = EnumC4471c0.COMPUTER_TAB_CLICKED.a();
            } else {
                if (iOrdinal4 != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                strA = "select_file_button_clicked";
            }
            bVar.a(UniversalUploadFlowEventLog.Companion.b(companion2, enumC4503nD2, strA));
            d0Var.h(w.a);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object E(kotlin.coroutines.jvm.internal.c r8) {
        /*
            r7 = this;
            boolean r0 = r8 instanceof com.quizlet.features.universaluploadflow.viewmodel.f
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.features.universaluploadflow.viewmodel.f r0 = (com.quizlet.features.universaluploadflow.viewmodel.f) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.features.universaluploadflow.viewmodel.f r0 = new com.quizlet.features.universaluploadflow.viewmodel.f
            r0.<init>(r7, r8)
        L18:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.features.universaluploadflow.viewmodel.g r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L77
        L29:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.features.universaluploadflow.logging.b r8 = r7.e
            r8.getClass()
            com.quizlet.eventlogger.model.UniversalUploadFlowEventLog$Companion r2 = com.quizlet.eventlogger.model.UniversalUploadFlowEventLog.b
            com.quizlet.data.model.m2 r4 = r8.b
            com.quizlet.generated.enums.n r5 = com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4.d(r4)
            java.lang.String r6 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r6)
            int r4 = r4.ordinal()
            if (r4 == 0) goto L5a
            if (r4 == r3) goto L5a
            r6 = 2
            if (r4 != r6) goto L54
            java.lang.String r4 = "upload_page_seen"
            goto L60
        L54:
            kotlin.NoWhenBranchMatchedException r8 = new kotlin.NoWhenBranchMatchedException
            r8.<init>()
            throw r8
        L5a:
            com.quizlet.generated.enums.c0 r4 = com.quizlet.generated.enums.EnumC4471c0.UPLOAD_SCREEN_VIEW
            java.lang.String r4 = r4.a()
        L60:
            com.quizlet.eventlogger.model.UniversalUploadFlowEventLog r2 = com.quizlet.eventlogger.model.UniversalUploadFlowEventLog.Companion.b(r2, r5, r4)
            r8.a(r2)
            r0.j = r7
            r0.m = r3
            androidx.work.impl.model.l r8 = r7.d
            com.quizlet.data.model.m2 r2 = r7.i
            java.lang.Object r8 = r8.m(r2, r0)
            if (r8 != r1) goto L76
            return r1
        L76:
            r0 = r7
        L77:
            com.quizlet.data.model.S r8 = (com.quizlet.data.model.S) r8
            if (r8 == 0) goto L89
            boolean r1 = r8.a
            if (r1 != 0) goto L89
            kotlinx.coroutines.flow.d0 r8 = r0.k
            com.quizlet.features.universaluploadflow.data.A r0 = com.quizlet.features.universaluploadflow.data.A.a
            r8.h(r0)
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        L89:
            kotlinx.coroutines.flow.s0 r1 = r0.j
        L8b:
            java.lang.Object r2 = r1.getValue()
            r3 = r2
            com.quizlet.features.universaluploadflow.data.K r3 = (com.quizlet.features.universaluploadflow.data.K) r3
            if (r8 == 0) goto L97
            java.lang.Integer r3 = r8.d
            goto L98
        L97:
            r3 = 0
        L98:
            com.quizlet.features.universaluploadflow.data.g r4 = new com.quizlet.features.universaluploadflow.data.g
            r4.<init>()
            com.quizlet.features.universaluploadflow.data.G r5 = new com.quizlet.features.universaluploadflow.data.G
            com.quizlet.data.model.m2 r6 = r0.i
            r5.<init>(r6, r4, r3)
            boolean r2 = r1.k(r2, r5)
            if (r2 == 0) goto L8b
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.universaluploadflow.viewmodel.g.E(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
