package com.quizlet.quizletandroid.ui.common.ads.prebid.creators;

import android.content.Context;
import android.view.View;
import androidx.glance.appwidget.protobuf.Z;
import com.fasterxml.jackson.databind.ObjectReader;
import com.google.android.gms.internal.ads.Zh;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.quizlet.data.model.Question;
import com.quizlet.data.model.QuestionPrompt;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.features.match.data.H;
import com.quizlet.generated.enums.D;
import com.quizlet.infra.legacysyncengine.net.f;
import com.quizlet.quizletandroid.ui.common.ads.prebid.g;
import com.quizlet.quizletandroid.ui.login.BaseSignupFragment;
import com.quizlet.quizletandroid.ui.profile.p;
import com.quizlet.quizletandroid.ui.startpage.nav2.OldHomeFragment;
import com.quizlet.quizletandroid.ui.startpage.nav2.Y;
import com.quizlet.remote.model.explanations.RemoteSimpleImage;
import com.quizlet.remote.model.explanations.question.RemoteQuestion;
import com.quizlet.remote.model.explanations.question.RemoteQuestionPrompt;
import com.quizlet.remote.model.explanations.solution.RemoteSolution;
import com.quizlet.remote.service.A;
import com.quizlet.remote.service.B;
import com.quizlet.remote.service.t;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.i;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;
import kotlin.r;
import kotlinx.coroutines.C5028l;
import kotlinx.serialization.internal.C5048d;
import okhttp3.J;
import org.wordpress.aztec.formatting.e;
import retrofit2.InterfaceC5186k;

/* loaded from: classes3.dex */
public final class c implements i, h, com.quizlet.features.setpage.utils.links.a, com.quizlet.remote.mapper.base.a, OnCompleteListener, InterfaceC5186k {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ c(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // com.quizlet.features.setpage.utils.links.a
    public String a(Context context, String url, String studySetTitle) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(studySetTitle, "studySetTitle");
        return AbstractC3053s1.e(((H) this.b).f, context);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 2:
                Boolean shouldShow = (Boolean) obj;
                Intrinsics.checkNotNullParameter(shouldShow, "shouldShow");
                return new Pair((com.quizlet.quizletandroid.ui.promo.rateus.b) this.b, shouldShow);
            case 3:
                ModelType it2 = (ModelType) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return ((f) ((Zh) this.b).c).c(it2);
            case 7:
                Intrinsics.checkNotNullParameter((Unit) obj, "it");
                return (View) this.b;
            default:
                ((io.reactivex.rxjava3.internal.operators.flowable.b) this.b).getClass();
                Object[] previews = {obj};
                Intrinsics.checkNotNullParameter(previews, "previews");
                ArrayList arrayList = new ArrayList(previews.length);
                for (Object obj2 : previews) {
                    Intrinsics.e(obj2, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.preview.dataclass.PreviewData");
                    arrayList.add((com.quizlet.quizletandroid.ui.preview.dataclass.a) obj2);
                }
                return arrayList;
        }
    }

    public Object b(String databaseValue) {
        Intrinsics.checkNotNullParameter(databaseValue, "databaseValue");
        return com.quizlet.shared.models.api.a.b.b(databaseValue, (C5048d) this.b);
    }

    @Override // retrofit2.InterfaceC5186k
    public Object convert(Object obj) {
        J j = (J) obj;
        try {
            return ((ObjectReader) this.b).readValue(j.f0().i0());
        } finally {
            j.close();
        }
    }

    public Object d(Object value) {
        Intrinsics.checkNotNullParameter(value, "value");
        return com.quizlet.shared.models.api.a.b.c((C5048d) this.b, value);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        return S.f(this, list);
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x005a A[Catch: Exception -> 0x0033, TryCatch #1 {Exception -> 0x0033, blocks: (B:12:0x002f, B:23:0x0050, B:25:0x005a, B:27:0x0063, B:29:0x006b, B:31:0x006f, B:33:0x0073, B:36:0x007d, B:38:0x0085, B:41:0x0089), top: B:60:0x002f }] */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0089 A[Catch: Exception -> 0x0033, TRY_LEAVE, TryCatch #1 {Exception -> 0x0033, blocks: (B:12:0x002f, B:23:0x0050, B:25:0x005a, B:27:0x0063, B:29:0x006b, B:31:0x006f, B:33:0x0073, B:36:0x007d, B:38:0x0085, B:41:0x0089), top: B:60:0x002f }] */
    /* JADX WARN: Removed duplicated region for block: B:51:0x009d  */
    /* JADX WARN: Removed duplicated region for block: B:61:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object f(kotlin.coroutines.jvm.internal.c r10) {
        /*
            r9 = this;
            boolean r0 = r10 instanceof com.quizlet.remote.model.qincentives.a
            if (r0 == 0) goto L13
            r0 = r10
            com.quizlet.remote.model.qincentives.a r0 = (com.quizlet.remote.model.qincentives.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.remote.model.qincentives.a r0 = new com.quizlet.remote.model.qincentives.a
            r0.<init>(r9, r10)
        L18:
            java.lang.Object r10 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            com.quizlet.data.model.k1 r3 = com.quizlet.data.model.C4142k1.b
            r4 = 403(0x193, float:5.65E-43)
            r5 = 400(0x190, float:5.6E-43)
            com.quizlet.data.model.k1 r6 = com.quizlet.data.model.C4142k1.c
            com.quizlet.data.model.k1 r7 = com.quizlet.data.model.C4142k1.a
            r8 = 1
            if (r2 == 0) goto L3d
            if (r2 != r8) goto L35
            com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.lang.Exception -> L33
            goto L50
        L33:
            r10 = move-exception
            goto L99
        L35:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L3d:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            java.lang.Object r10 = r9.b     // Catch: java.lang.Exception -> L97
            com.quizlet.remote.service.t r10 = (com.quizlet.remote.service.t) r10     // Catch: java.lang.Exception -> L97
            r0.j = r9     // Catch: java.lang.Exception -> L97
            r0.m = r8     // Catch: java.lang.Exception -> L97
            java.lang.Object r10 = r10.a(r0)     // Catch: java.lang.Exception -> L97
            if (r10 != r1) goto L4f
            return r1
        L4f:
            r0 = r9
        L50:
            retrofit2.K r10 = (retrofit2.K) r10     // Catch: java.lang.Exception -> L33
            okhttp3.H r1 = r10.a     // Catch: java.lang.Exception -> L33
            boolean r1 = r1.d()     // Catch: java.lang.Exception -> L33
            if (r1 == 0) goto L89
            r0.getClass()     // Catch: java.lang.Exception -> L33
            java.lang.Object r10 = r10.b     // Catch: java.lang.Exception -> L33
            com.quizlet.remote.model.base.ApiThreeWrapper r10 = (com.quizlet.remote.model.base.ApiThreeWrapper) r10     // Catch: java.lang.Exception -> L33
            if (r10 == 0) goto L7a
            com.quizlet.remote.model.base.ApiResponse r10 = r10.a()     // Catch: java.lang.Exception -> L33
            com.quizlet.remote.model.user.FullUserResponse r10 = (com.quizlet.remote.model.user.FullUserResponse) r10     // Catch: java.lang.Exception -> L33
            if (r10 == 0) goto L7a
            com.quizlet.remote.model.user.FullUserModels r10 = r10.d     // Catch: java.lang.Exception -> L33
            if (r10 == 0) goto L7a
            java.util.List r10 = r10.a     // Catch: java.lang.Exception -> L33
            if (r10 == 0) goto L7a
            java.lang.Object r10 = kotlin.collections.CollectionsKt.firstOrNull(r10)     // Catch: java.lang.Exception -> L33
            com.quizlet.remote.model.user.RemoteFullUser r10 = (com.quizlet.remote.model.user.RemoteFullUser) r10     // Catch: java.lang.Exception -> L33
            goto L7b
        L7a:
            r10 = 0
        L7b:
            if (r10 == 0) goto L88
            com.quizlet.data.model.i0 r10 = com.quizlet.quizletandroid.managers.upgrade.a.d(r10)     // Catch: java.lang.Exception -> L33
            int r10 = r10.e     // Catch: java.lang.Exception -> L33
            if (r10 != r8) goto L88
            com.quizlet.data.model.l1 r10 = com.quizlet.data.model.C4145l1.a     // Catch: java.lang.Exception -> L33
            return r10
        L88:
            return r7
        L89:
            okhttp3.H r10 = r10.a     // Catch: java.lang.Exception -> L33
            int r10 = r10.d     // Catch: java.lang.Exception -> L33
            r0.getClass()     // Catch: java.lang.Exception -> L33
            if (r10 == r5) goto L96
            if (r10 == r4) goto L95
            return r6
        L95:
            return r3
        L96:
            return r7
        L97:
            r10 = move-exception
            r0 = r9
        L99:
            boolean r1 = r10 instanceof retrofit2.HttpException
            if (r1 == 0) goto Lac
            retrofit2.HttpException r10 = (retrofit2.HttpException) r10
            r0.getClass()
            int r10 = r10.a
            if (r10 == r5) goto Laa
            if (r10 == r4) goto Lab
            r3 = r6
            goto Lab
        Laa:
            r3 = r7
        Lab:
            r6 = r3
        Lac:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c.f(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.quizlet.remote.mapper.base.a
    /* renamed from: g, reason: merged with bridge method [inline-methods] */
    public Question c(RemoteQuestion remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        RemoteQuestionPrompt remoteQuestionPrompt = remote.d;
        String str = remoteQuestionPrompt.a;
        RemoteSimpleImage remoteSimpleImage = remoteQuestionPrompt.b;
        QuestionPrompt questionPrompt = new QuestionPrompt(str, remoteSimpleImage != null ? p.i(remoteSimpleImage) : null);
        String str2 = remote.c;
        if (str2 == null) {
            str2 = "";
        }
        String str3 = str2;
        List list = remote.g;
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            int iIntValue = ((Number) it2.next()).intValue();
            com.quizlet.generated.enums.C c = D.Companion;
            Integer numValueOf = Integer.valueOf(iIntValue);
            c.getClass();
            arrayList.add(com.quizlet.generated.enums.C.a(numValueOf));
        }
        List list2 = remote.i;
        ArrayList arrayList2 = new ArrayList(C.q(list2, 10));
        Iterator it3 = list2.iterator();
        while (it3.hasNext()) {
            arrayList2.add(((com.quizlet.quizletandroid.ui.common.images.capture.a) this.b).c((RemoteSolution) it3.next()));
        }
        return new Question(remote.a, remote.b, str3, remote.e, arrayList, questionPrompt, remote.f, remote.h, arrayList2);
    }

    @Override // com.google.android.gms.tasks.OnCompleteListener
    public void onComplete(Task task) {
        Exception excG = task.g();
        C5028l c5028l = (C5028l) this.b;
        if (excG != null) {
            kotlin.p pVar = r.b;
            c5028l.resumeWith(Z.b(excG));
        } else if (task.j()) {
            c5028l.b(null);
        } else {
            kotlin.p pVar2 = r.b;
            c5028l.resumeWith(task.h());
        }
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        switch (this.a) {
            case 1:
                String email = (String) obj;
                Intrinsics.checkNotNullParameter(email, "email");
                if (((BaseSignupFragment) this.b).j != null) {
                    return com.quizlet.qutils.string.c.c(email);
                }
                Intrinsics.m("emailUtil");
                throw null;
            default:
                Integer it2 = (Integer) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                if (it2.intValue() == 0) {
                    Y y = ((OldHomeFragment) this.b).t;
                    if (y == null) {
                        Intrinsics.m("viewModel");
                        throw null;
                    }
                    if (y.t.c()) {
                        return true;
                    }
                }
                return false;
        }
    }

    public c(A signUpValidationService) {
        this.a = 9;
        Intrinsics.checkNotNullParameter(signUpValidationService, "signUpValidationService");
        this.b = signUpValidationService;
    }

    public c(e listStyle) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(listStyle, "listStyle");
        this.b = listStyle;
    }

    public c(C5048d serializer) {
        this.a = 12;
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        this.b = serializer;
    }

    public c(p remoteSimpleImageMapper, com.quizlet.quizletandroid.ui.common.images.capture.a remoteSolutionMapper) {
        this.a = 8;
        Intrinsics.checkNotNullParameter(remoteSimpleImageMapper, "remoteSimpleImageMapper");
        Intrinsics.checkNotNullParameter(remoteSolutionMapper, "remoteSolutionMapper");
        this.b = remoteSolutionMapper;
    }

    public c(B service) {
        this.a = 11;
        Intrinsics.checkNotNullParameter(service, "service");
        this.b = service;
    }

    public c(g bannerAdManager) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(bannerAdManager, "bannerAdManager");
        this.b = bannerAdManager;
    }

    public c(t service, com.quizlet.quizletandroid.managers.upgrade.a mapper) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.b = service;
    }

    public c(com.google.android.gms.measurement.internal.J expertSolutionsUpsellManager) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(expertSolutionsUpsellManager, "expertSolutionsUpsellManager");
        this.b = expertSolutionsUpsellManager;
    }
}
