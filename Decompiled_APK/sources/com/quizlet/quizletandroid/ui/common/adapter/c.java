package com.quizlet.quizletandroid.ui.common.adapter;

import android.content.Context;
import android.content.res.Resources;
import android.net.Uri;
import com.google.android.gms.internal.mlkit_vision_barcode.Q;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.quizlet.data.model.A1;
import com.quizlet.data.model.C4136i1;
import com.quizlet.data.model.C4139j1;
import com.quizlet.data.model.E0;
import com.quizlet.data.model.School;
import com.quizlet.quizletandroid.R;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.base.PagingInfo;
import com.quizlet.remote.model.explanations.exercise.RemoteExerciseDetails;
import com.quizlet.remote.model.explanations.textbook.RemoteTextbook;
import com.quizlet.remote.model.qclass.ClassModels;
import com.quizlet.remote.model.qclass.ClassResponse;
import com.quizlet.remote.model.qclass.RemoteClass;
import com.quizlet.remote.model.school.RemoteSchool;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.B;
import okhttp3.r;
import okio.C5091h;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class c implements d, com.quizlet.remote.mapper.base.a, io.reactivex.rxjava3.functions.h {
    public static ArrayList d(List list) {
        ArrayList arrayListM = assistantMode.refactored.a.m("protocols", list);
        for (Object obj : list) {
            if (((B) obj) != B.HTTP_1_0) {
                arrayListM.add(obj);
            }
        }
        ArrayList arrayList = new ArrayList(C.q(arrayListM, 10));
        Iterator it2 = arrayListM.iterator();
        while (it2.hasNext()) {
            arrayList.add(((B) it2.next()).a);
        }
        return arrayList;
    }

    public static byte[] f(List protocols) {
        Intrinsics.checkNotNullParameter(protocols, "protocols");
        C5091h c5091h = new C5091h();
        Iterator it2 = d(protocols).iterator();
        while (it2.hasNext()) {
            String str = (String) it2.next();
            c5091h.p0(str.length());
            c5091h.u0(str);
        }
        return c5091h.B(c5091h.b);
    }

    public static boolean g() {
        return "Dalvik".equals(System.getProperty("java.vm.name"));
    }

    public static void h(int i, long j, Context context) throws Resources.NotFoundException {
        String string;
        Intrinsics.checkNotNullParameter(context, "context");
        Resources resources = context.getResources();
        if (i == 1) {
            string = resources.getString(R.string.report_content_set_title);
            Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        } else if (i != 4) {
            string = resources.getString(R.string.report_content_user_title);
            Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        } else {
            string = resources.getString(R.string.report_content_class_title);
            Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        }
        com.quizlet.quizletandroid.ui.webpages.a aVar = com.quizlet.quizletandroid.ui.webpages.a.a;
        String url = "https://quizlet.com/oauthweb/flags/reporting-flow?modelType=" + i + "&modelId=" + j;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(url, "url");
        Uri uri = Uri.parse(url);
        Intrinsics.checkNotNullExpressionValue(uri, "parse(...)");
        if (com.quizlet.quizletandroid.ui.webpages.a.b.contains(uri.getHost())) {
            aVar.b(context, url, string);
        }
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.d
    public void a() {
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r4v0, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r4v1, types: [java.lang.Iterable] */
    /* JADX WARN: Type inference failed for: r4v2, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r5v0, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r5v1, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r5v2, types: [java.util.ArrayList] */
    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        ?? arrayList;
        ?? arrayList2;
        PagingInfo pagingInfo;
        ClassModels classModels;
        List<RemoteClass> list;
        Object next;
        ClassModels classModels2;
        List list2;
        K response = (K) obj;
        Intrinsics.checkNotNullParameter(response, "response");
        r rVar = response.a.f;
        ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) response.b;
        A1 a1I = null;
        ClassResponse classResponse = apiThreeWrapper != null ? (ClassResponse) apiThreeWrapper.a() : null;
        if (classResponse == null || (classModels2 = classResponse.d) == null || (list2 = classModels2.b) == null) {
            arrayList = kotlin.collections.K.a;
        } else {
            arrayList = new ArrayList(C.q(list2, 10));
            Iterator it2 = list2.iterator();
            while (it2.hasNext()) {
                arrayList.add(com.quizlet.remote.model.school.a.a((RemoteSchool) it2.next()));
            }
        }
        if (classResponse == null || (classModels = classResponse.d) == null || (list = classModels.a) == null) {
            arrayList2 = kotlin.collections.K.a;
        } else {
            arrayList2 = new ArrayList(C.q(list, 10));
            for (RemoteClass remoteClass : list) {
                Iterator it3 = arrayList.iterator();
                while (true) {
                    if (!it3.hasNext()) {
                        next = null;
                        break;
                    }
                    next = it3.next();
                    if (((School) next).a == remoteClass.d) {
                        break;
                    }
                }
                arrayList2.add(new C4136i1(com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a.d(remoteClass), (School) next));
            }
        }
        if (classResponse != null && (pagingInfo = classResponse.a) != null) {
            a1I = com.quizlet.quizletandroid.ui.folder.logging.a.i(pagingInfo);
        }
        return new C4139j1(arrayList2, a1I, Q.a(rVar));
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.d
    public void b() {
    }

    @Override // com.quizlet.remote.mapper.base.a
    public Object c(Object obj) {
        RemoteExerciseDetails remote = (RemoteExerciseDetails) obj;
        Intrinsics.checkNotNullParameter(remote, "remote");
        long j = remote.a;
        RemoteTextbook remoteTextbook = remote.k;
        long j2 = remoteTextbook.a;
        String str = remoteTextbook.c;
        String str2 = str == null ? "" : str;
        String str3 = remoteTextbook.e;
        String str4 = str3 == null ? "" : str3;
        Boolean bool = remoteTextbook.h;
        boolean zBooleanValue = bool != null ? bool.booleanValue() : false;
        Long l = remote.o;
        return new E0(j, remote.b, remote.c, remote.d, remote.g, remote.f, l != null ? l.longValue() : 0L, remote.i, j2, remoteTextbook.b, str2, str4, zBooleanValue);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        return S.f(this, list);
    }
}
