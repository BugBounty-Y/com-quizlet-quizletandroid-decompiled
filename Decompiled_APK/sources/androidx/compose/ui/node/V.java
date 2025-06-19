package androidx.compose.ui.node;

import android.content.Context;
import androidx.compose.foundation.lazy.layout.C0429a;
import androidx.work.C1422c;
import androidx.work.impl.C1433e;
import androidx.work.impl.WorkDatabase;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.ads.BinderC2408nm;
import com.google.android.gms.internal.ads.C2067fq;
import com.google.android.gms.internal.ads.C2257k6;
import com.google.android.gms.internal.ads.C2429o6;
import com.google.android.gms.internal.ads.C2881yn;
import com.google.android.gms.internal.ads.Ev;
import com.google.android.gms.internal.ads.Hk;
import com.google.android.gms.internal.ads.InterfaceC2529qe;
import com.google.android.gms.internal.ads.L9;
import com.google.android.gms.internal.ads.P4;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.generated.enums.A1;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class V implements Ev {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;
    public Object d;
    public Object e;
    public Object f;
    public Object g;
    public Object h;
    public Object i;

    public /* synthetic */ V() {
        this.a = 1;
    }

    public static final void a(V v, androidx.compose.ui.p pVar, a0 a0Var) {
        v.getClass();
        for (androidx.compose.ui.p pVar2 = pVar.e; pVar2 != null; pVar2 = pVar2.e) {
            if (pVar2 == X.a) {
                E eS = ((E) v.b).s();
                a0Var.n = eS != null ? (C0923t) eS.w.c : null;
                v.d = a0Var;
                return;
            } else {
                if ((pVar2.c & 2) != 0) {
                    return;
                }
                pVar2.L0(a0Var);
            }
        }
    }

    public static boolean b(List list, Set set, int i) {
        List listP0 = CollectionsKt.p0(list, i);
        if (listP0 != null && listP0.isEmpty()) {
            return false;
        }
        Iterator it2 = listP0.iterator();
        while (it2.hasNext()) {
            if (set.contains((String) it2.next())) {
                return true;
            }
        }
        return false;
    }

    public static androidx.compose.ui.p d(androidx.compose.ui.o oVar, androidx.compose.ui.p pVar) {
        androidx.compose.ui.p pVarL;
        if (oVar instanceof T) {
            pVarL = ((T) oVar).l();
            pVarL.c = b0.g(pVarL);
        } else {
            C0907c c0907c = new C0907c();
            c0907c.c = b0.e(oVar);
            c0907c.n = oVar;
            c0907c.p = new HashSet();
            pVarL = c0907c;
        }
        if (pVarL.m) {
            W4.f("A ModifierNodeElement cannot return an already attached node from create() ");
            throw null;
        }
        pVarL.i = true;
        androidx.compose.ui.p pVar2 = pVar.f;
        if (pVar2 != null) {
            pVar2.e = pVarL;
            pVarL.f = pVar2;
        }
        pVar.f = pVarL;
        pVarL.e = pVar;
        return pVarL;
    }

    public static androidx.compose.ui.p e(androidx.compose.ui.p pVar) {
        boolean z = pVar.m;
        if (z) {
            androidx.collection.C c = b0.a;
            if (!z) {
                W4.f("autoInvalidateRemovedNode called on unattached node");
                throw null;
            }
            b0.b(pVar, -1, 2);
            pVar.J0();
            pVar.D0();
        }
        androidx.compose.ui.p pVar2 = pVar.f;
        androidx.compose.ui.p pVar3 = pVar.e;
        if (pVar2 != null) {
            pVar2.e = pVar3;
            pVar.f = null;
        }
        if (pVar3 != null) {
            pVar3.f = pVar2;
            pVar.e = null;
        }
        Intrinsics.d(pVar3);
        return pVar3;
    }

    public static boolean f(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Character chValueOf = str.length() == 0 ? null : Character.valueOf(str.charAt(0));
        if (chValueOf != null) {
            return Character.isUpperCase(chValueOf.charValue());
        }
        return true;
    }

    public static void l(androidx.compose.ui.o oVar, androidx.compose.ui.o oVar2, androidx.compose.ui.p pVar) {
        if ((oVar instanceof T) && (oVar2 instanceof T)) {
            W w = X.a;
            Intrinsics.e(pVar, "null cannot be cast to non-null type T of androidx.compose.ui.node.NodeChainKt.updateUnsafe");
            ((T) oVar2).n(pVar);
            if (pVar.m) {
                b0.d(pVar);
                return;
            } else {
                pVar.j = true;
                return;
            }
        }
        if (!(pVar instanceof C0907c)) {
            throw new IllegalStateException("Unknown Modifier.Node type");
        }
        C0907c c0907c = (C0907c) pVar;
        if (c0907c.m) {
            c0907c.N0();
        }
        c0907c.n = oVar2;
        c0907c.c = b0.e(oVar2);
        if (c0907c.m) {
            c0907c.M0(false);
        }
        if (pVar.m) {
            b0.d(pVar);
        } else {
            pVar.j = true;
        }
    }

    public com.google.android.datatransport.cct.internal.s c(androidx.lifecycle.m0 savedStateHandle) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        C0429a c0429a = (C0429a) this.c;
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        com.quizlet.features.infra.basestudy.data.models.x xVarB = AbstractC3249r5.b(savedStateHandle);
        A1 a1 = xVarB.g;
        com.google.android.gms.measurement.internal.N highScoresManager = new com.google.android.gms.measurement.internal.N(c0429a.a, xVarB.a, xVarB.c, a1);
        com.quizlet.features.infra.basestudy.manager.f studyModeManager = ((com.quizlet.features.infra.basestudy.manager.a) this.d).a(savedStateHandle);
        io.reactivex.rxjava3.core.o ioScheduler = (io.reactivex.rxjava3.core.o) this.i;
        UserInfoCache userInfoCache = (UserInfoCache) this.b;
        com.quizlet.features.match.highscore.b highScoresState = (com.quizlet.features.match.highscore.b) this.f;
        IQuizletApiClient quizletApiClient = (IQuizletApiClient) this.g;
        com.quizlet.infra.legacysyncengine.managers.i saveManager = (com.quizlet.infra.legacysyncengine.managers.i) this.e;
        DatabaseHelper databaseHelper = (DatabaseHelper) this.h;
        Intrinsics.checkNotNullParameter(highScoresManager, "highScoresManager");
        Intrinsics.checkNotNullParameter(studyModeManager, "studyModeManager");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(saveManager, "saveManager");
        Intrinsics.checkNotNullParameter(highScoresState, "highScoresState");
        Intrinsics.checkNotNullParameter(quizletApiClient, "quizletApiClient");
        Intrinsics.checkNotNullParameter(databaseHelper, "databaseHelper");
        Intrinsics.checkNotNullParameter(ioScheduler, "ioScheduler");
        com.google.android.datatransport.cct.internal.s sVar = new com.google.android.datatransport.cct.internal.s();
        sVar.b = highScoresManager;
        sVar.c = studyModeManager;
        sVar.d = userInfoCache;
        sVar.e = saveManager;
        sVar.f = highScoresState;
        sVar.g = quizletApiClient;
        sVar.a = databaseHelper;
        sVar.h = ioScheduler;
        sVar.i = com.google.android.gms.measurement.internal.Z.f("create(...)");
        return sVar;
    }

    public List g() {
        return (List) ((kotlin.u) this.g).getValue();
    }

    public boolean h(int i) {
        return (i & ((androidx.compose.ui.p) this.f).d) != 0;
    }

    public void i() {
        for (androidx.compose.ui.p pVar = (androidx.compose.ui.p) this.f; pVar != null; pVar = pVar.f) {
            pVar.I0();
            if (pVar.i) {
                b0.a(pVar);
            }
            if (pVar.j) {
                b0.d(pVar);
            }
            pVar.i = false;
            pVar.j = false;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:103:0x0217, code lost:
    
        r11 = r27 + 2;
        r5 = r23;
     */
    /* JADX WARN: Code restructure failed: missing block: B:104:0x021d, code lost:
    
        r3 = r3 + 1;
        r10 = r19;
        r5 = r20;
        r11 = r25;
        r12 = r28;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x013a, code lost:
    
        r25 = r11;
        r28 = r12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x0140, code lost:
    
        if ((r18 % 2) != 0) goto L57;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x0142, code lost:
    
        r5 = 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x0144, code lost:
    
        r5 = r32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x0146, code lost:
    
        r11 = r10;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x0147, code lost:
    
        if (r11 > r3) goto L166;
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x0149, code lost:
    
        if (r11 == r10) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:61:0x014b, code lost:
    
        if (r11 == r3) goto L65;
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x014d, code lost:
    
        r23 = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x015b, code lost:
    
        if (r25[(r11 + 1) + r16] >= r25[(r11 - 1) + r16]) goto L66;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x015e, code lost:
    
        r23 = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x0160, code lost:
    
        r5 = r25[(r11 - 1) + r16];
        r12 = r5 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:67:0x0169, code lost:
    
        r23 = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:68:0x016b, code lost:
    
        r5 = r25[(r11 + 1) + r16];
        r12 = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:69:0x0172, code lost:
    
        r21 = r6 - ((r14 - r12) - r11);
     */
    /* JADX WARN: Code restructure failed: missing block: B:70:0x0178, code lost:
    
        if (r3 == 0) goto L74;
     */
    /* JADX WARN: Code restructure failed: missing block: B:71:0x017a, code lost:
    
        if (r12 == r5) goto L73;
     */
    /* JADX WARN: Code restructure failed: missing block: B:73:0x017d, code lost:
    
        r24 = r21 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:74:0x0180, code lost:
    
        r24 = r21;
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:0x0182, code lost:
    
        r21 = r5;
        r5 = r21;
     */
    /* JADX WARN: Code restructure failed: missing block: B:76:0x0188, code lost:
    
        if (r12 <= r13) goto L171;
     */
    /* JADX WARN: Code restructure failed: missing block: B:77:0x018a, code lost:
    
        if (r5 <= r9) goto L172;
     */
    /* JADX WARN: Code restructure failed: missing block: B:78:0x018c, code lost:
    
        r26 = r5;
        r27 = r11;
     */
    /* JADX WARN: Code restructure failed: missing block: B:79:0x0198, code lost:
    
        if (r0.q(r12 - 1, r26 - 1) == false) goto L173;
     */
    /* JADX WARN: Code restructure failed: missing block: B:80:0x019a, code lost:
    
        r12 = r12 - 1;
        r5 = r26 - 1;
        r11 = r27;
     */
    /* JADX WARN: Code restructure failed: missing block: B:81:0x01a1, code lost:
    
        r26 = r5;
        r27 = r11;
     */
    /* JADX WARN: Code restructure failed: missing block: B:82:0x01a5, code lost:
    
        r25[r16 + r27] = r12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:83:0x01a9, code lost:
    
        if (r23 == 0) goto L167;
     */
    /* JADX WARN: Code restructure failed: missing block: B:84:0x01ab, code lost:
    
        r5 = r18 - r27;
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x01ad, code lost:
    
        if (r5 < r10) goto L168;
     */
    /* JADX WARN: Code restructure failed: missing block: B:86:0x01af, code lost:
    
        if (r5 > r3) goto L169;
     */
    /* JADX WARN: Code restructure failed: missing block: B:88:0x01b5, code lost:
    
        if (r19[r16 + r5] < r12) goto L170;
     */
    /* JADX WARN: Code restructure failed: missing block: B:89:0x01b7, code lost:
    
        r28[r32] = r12;
        r10 = 1;
        r28[1] = r26;
        r28[r31] = r21;
        r28[3] = r24;
        r28[4] = 1;
     */
    /* JADX WARN: Removed duplicated region for block: B:33:0x00eb A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00f1  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x010e  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x0130  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void j(int r31, androidx.compose.runtime.collection.b r32, androidx.compose.runtime.collection.b r33, androidx.compose.ui.p r34, boolean r35) {
        /*
            Method dump skipped, instructions count: 886
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.node.V.j(int, androidx.compose.runtime.collection.b, androidx.compose.runtime.collection.b, androidx.compose.ui.p, boolean):void");
    }

    public void k() {
        E e;
        C0928y c0928y;
        androidx.compose.ui.p pVar = ((o0) this.e).e;
        a0 a0Var = (C0923t) this.c;
        androidx.compose.ui.p pVar2 = pVar;
        while (true) {
            e = (E) this.b;
            if (pVar2 == null) {
                break;
            }
            InterfaceC0926w interfaceC0926wG = AbstractC0910f.g(pVar2);
            if (interfaceC0926wG != null) {
                a0 a0Var2 = pVar2.h;
                if (a0Var2 != null) {
                    C0928y c0928y2 = (C0928y) a0Var2;
                    InterfaceC0926w interfaceC0926w = c0928y2.K;
                    c0928y2.u1(interfaceC0926wG);
                    c0928y = c0928y2;
                    if (interfaceC0926w != pVar2) {
                        f0 f0Var = c0928y2.D;
                        c0928y = c0928y2;
                        if (f0Var != null) {
                            f0Var.invalidate();
                            c0928y = c0928y2;
                        }
                    }
                } else {
                    C0928y c0928y3 = new C0928y(e, interfaceC0926wG);
                    pVar2.L0(c0928y3);
                    c0928y = c0928y3;
                }
                a0Var.n = c0928y;
                c0928y.m = a0Var;
                a0Var = c0928y;
            } else {
                pVar2.L0(a0Var);
            }
            pVar2 = pVar2.e;
        }
        E eS = e.s();
        a0Var.n = eS != null ? (C0923t) eS.w.c : null;
        this.d = a0Var;
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x011a A[Catch: all -> 0x00fa, DONT_GENERATE, TRY_LEAVE, TryCatch #0 {all -> 0x00fa, blocks: (B:12:0x00e9, B:14:0x00ef, B:16:0x00f6, B:20:0x00fc, B:22:0x0107, B:24:0x010b, B:26:0x0116, B:28:0x011a), top: B:41:0x00e9 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.util.HashMap m() {
        /*
            Method dump skipped, instructions count: 336
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.node.V.m():java.util.HashMap");
    }

    public String toString() {
        switch (this.a) {
            case 0:
                StringBuilder sb = new StringBuilder("[");
                androidx.compose.ui.p pVar = (androidx.compose.ui.p) this.f;
                o0 o0Var = (o0) this.e;
                if (pVar == o0Var) {
                    sb.append("]");
                } else {
                    while (true) {
                        if (pVar != null && pVar != o0Var) {
                            sb.append(String.valueOf(pVar));
                            if (pVar.f == o0Var) {
                                sb.append("]");
                            } else {
                                sb.append(",");
                                pVar = pVar.f;
                            }
                        }
                    }
                }
                String string = sb.toString();
                Intrinsics.checkNotNullExpressionValue(string, "StringBuilder().apply(builderAction).toString()");
                return string;
            default:
                return super.toString();
        }
    }

    @Override // com.google.android.gms.internal.ads.Ev
    /* renamed from: zza */
    public com.google.common.util.concurrent.e mo19zza() {
        L9 l9 = com.google.android.gms.ads.internal.j.C.d;
        com.bumptech.glide.load.engine.cache.f fVar = new com.bumptech.glide.load.engine.cache.f(0, 0, 0);
        C2429o6 c2429o6 = new C2429o6();
        Context context = (Context) this.b;
        VersionInfoParcel versionInfoParcel = (VersionInfoParcel) this.d;
        androidx.work.impl.model.c cVar = (androidx.work.impl.model.c) this.e;
        C2067fq c2067fq = (C2067fq) this.g;
        InterfaceC2529qe interfaceC2529qeG = L9.g(context, cVar, fVar, versionInfoParcel, (P4) this.c, c2429o6, null, (Hk) this.h, (BinderC2408nm) this.f, null, null, null, c2067fq, "", false, false);
        C2257k6 c2257k6 = new C2257k6(interfaceC2529qeG);
        interfaceC2529qeG.L().g = new C2881yn(c2257k6, 10);
        interfaceC2529qeG.loadUrl((String) this.i);
        return c2257k6;
    }

    public /* synthetic */ V(Object obj, Object obj2, Object obj3, Object obj4, Object obj5, Object obj6, Object obj7, Object obj8, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = obj4;
        this.f = obj5;
        this.g = obj6;
        this.h = obj7;
        this.i = obj8;
    }

    public V(String text, String textLanguageCode, String oppositeText, String oppositeLanguageCode) {
        this.a = 3;
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(textLanguageCode, "textLanguageCode");
        Intrinsics.checkNotNullParameter(oppositeText, "oppositeText");
        Intrinsics.checkNotNullParameter(oppositeLanguageCode, "oppositeLanguageCode");
        this.b = text;
        this.c = textLanguageCode;
        this.d = oppositeText;
        this.e = oppositeLanguageCode;
        this.f = kotlin.l.b(new assistantMode.utils.classification.c(this, 2));
        this.g = kotlin.l.b(new assistantMode.utils.classification.c(this, 3));
        this.h = kotlin.l.b(new assistantMode.utils.classification.c(this, 0));
        this.i = kotlin.l.b(new assistantMode.utils.classification.c(this, 1));
    }

    public V(androidx.work.impl.model.v getFolderUseCase, UserInfoCache userInfoCache, com.quizlet.data.connectivity.a networkStatus, com.quizlet.data.repository.course.membership.c coursePoweredFoldersFeature, com.quizlet.data.repository.activitycenter.b copyFolderStateUseCase, com.quizlet.data.repository.user.a subFolderFeature, com.quizlet.data.repository.user.a quizletPoweredFoldersFeature, com.google.android.material.floatingactionbutton.c showAddQPFToLibraryTooltipUseCase) {
        this.a = 7;
        Intrinsics.checkNotNullParameter(getFolderUseCase, "getFolderUseCase");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(coursePoweredFoldersFeature, "coursePoweredFoldersFeature");
        Intrinsics.checkNotNullParameter(copyFolderStateUseCase, "copyFolderStateUseCase");
        Intrinsics.checkNotNullParameter(subFolderFeature, "subFolderFeature");
        Intrinsics.checkNotNullParameter(quizletPoweredFoldersFeature, "quizletPoweredFoldersFeature");
        Intrinsics.checkNotNullParameter(showAddQPFToLibraryTooltipUseCase, "showAddQPFToLibraryTooltipUseCase");
        this.b = getFolderUseCase;
        this.c = userInfoCache;
        this.d = networkStatus;
        this.e = coursePoweredFoldersFeature;
        this.f = copyFolderStateUseCase;
        this.g = subFolderFeature;
        this.h = quizletPoweredFoldersFeature;
        this.i = showAddQPFToLibraryTooltipUseCase;
    }

    public V(UserInfoCache userInfoCache, C0429a matchHighScoresManagerFactory, com.quizlet.features.infra.basestudy.manager.a studyModeManagerFactory, com.quizlet.infra.legacysyncengine.managers.i saveManager, com.quizlet.features.match.highscore.b highScoresState, IQuizletApiClient quizletApiClient, DatabaseHelper databaseHelper, io.reactivex.rxjava3.core.o ioScheduler) {
        this.a = 8;
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(matchHighScoresManagerFactory, "matchHighScoresManagerFactory");
        Intrinsics.checkNotNullParameter(studyModeManagerFactory, "studyModeManagerFactory");
        Intrinsics.checkNotNullParameter(saveManager, "saveManager");
        Intrinsics.checkNotNullParameter(highScoresState, "highScoresState");
        Intrinsics.checkNotNullParameter(quizletApiClient, "quizletApiClient");
        Intrinsics.checkNotNullParameter(databaseHelper, "databaseHelper");
        Intrinsics.checkNotNullParameter(ioScheduler, "ioScheduler");
        this.b = userInfoCache;
        this.c = matchHighScoresManagerFactory;
        this.d = studyModeManagerFactory;
        this.e = saveManager;
        this.f = highScoresState;
        this.g = quizletApiClient;
        this.h = databaseHelper;
        this.i = ioScheduler;
    }

    public V(E e) {
        this.a = 0;
        this.b = e;
        C0923t c0923t = new C0923t(e);
        this.c = c0923t;
        this.d = c0923t;
        o0 o0Var = c0923t.K;
        this.e = o0Var;
        this.f = o0Var;
    }

    public V(ModelIdentityProvider modelIdentityProvider, com.quizlet.infra.legacysyncengine.net.listeners.d dVar, ExecutionRouter executionRouter, androidx.work.impl.model.c cVar, com.quizlet.infra.legacysyncengine.tasks.parse.f fVar, com.google.android.datatransport.cct.internal.s sVar, com.squareup.otto.c cVar2, DatabaseHelper databaseHelper, IQuizletApiClient iQuizletApiClient) {
        this.a = 9;
        this.b = dVar;
        this.c = executionRouter;
        this.d = cVar;
        this.e = fVar;
        this.f = sVar;
        this.g = cVar2;
        this.h = databaseHelper;
        this.i = iQuizletApiClient;
    }

    public V(Context context, C1422c configuration, androidx.work.impl.utils.taskexecutor.c workTaskExecutor, C1433e foregroundProcessor, WorkDatabase workDatabase, androidx.work.impl.model.q workSpec, ArrayList tags) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(configuration, "configuration");
        Intrinsics.checkNotNullParameter(workTaskExecutor, "workTaskExecutor");
        Intrinsics.checkNotNullParameter(foregroundProcessor, "foregroundProcessor");
        Intrinsics.checkNotNullParameter(workDatabase, "workDatabase");
        Intrinsics.checkNotNullParameter(workSpec, "workSpec");
        Intrinsics.checkNotNullParameter(tags, "tags");
        this.b = configuration;
        this.c = workTaskExecutor;
        this.d = foregroundProcessor;
        this.e = workDatabase;
        this.f = workSpec;
        this.g = tags;
        Context applicationContext = context.getApplicationContext();
        Intrinsics.checkNotNullExpressionValue(applicationContext, "context.applicationContext");
        this.h = applicationContext;
        this.i = new com.google.android.gms.internal.appset.e(4);
    }
}
