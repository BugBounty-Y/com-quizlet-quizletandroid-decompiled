package com.quizlet.quizletandroid.ui.login;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.ads.Zh;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.C4154o1;
import com.quizlet.data.model.TableOfContentItem;
import com.quizlet.data.model.TableOfContents;
import com.quizlet.data.model.Textbook;
import com.quizlet.data.model.Z;
import com.quizlet.generated.enums.EnumC4497l;
import com.quizlet.generated.enums.W0;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import com.quizlet.quizletandroid.ui.setpage.terms.TermListFragment;
import com.quizlet.quizletandroid.ui.startpage.nav2.Y;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.P;
import com.quizlet.remote.model.explanations.search.RemoteSearchResultQuestion;
import com.quizlet.remote.model.explanations.textbook.RemoteTextbook;
import com.quizlet.remote.model.search.SearchBannerWrapper;
import com.quizlet.remote.service.InterfaceC4779f;
import io.reactivex.rxjava3.internal.operators.observable.E;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.Pair;
import kotlin.collections.CollectionsKt;
import kotlin.collections.F;
import kotlin.collections.K;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;
import kotlinx.serialization.descriptors.SerialDescriptor;
import retrofit2.C5183h;
import retrofit2.HttpException;
import retrofit2.InterfaceC5179d;
import retrofit2.InterfaceC5182g;

/* loaded from: classes3.dex */
public final class h implements io.reactivex.rxjava3.functions.h, com.quizlet.quizletandroid.ui.common.adapter.d, com.quizlet.remote.mapper.base.b, InterfaceC5182g {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ h(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public static void i(h hVar, String authProvider, boolean z, Boolean bool, Boolean bool2, Boolean bool3, Boolean bool4) {
        Intrinsics.checkNotNullParameter(authProvider, "authProvider");
        com.snowplowanalytics.snowplow.payload.a aVar = new com.snowplowanalytics.snowplow.payload.a("iglu:com.quizlet/login/jsonschema/1-0-0", V.f(new Pair("auth_provider", authProvider), new Pair("is_signup", Boolean.valueOf(z))));
        Map mapF = V.f(new Pair("uid", null), new Pair("is_free_teacher", bool), new Pair("is_logged_in", Boolean.TRUE), new Pair("is_plus", bool2), new Pair("is_underage", bool4), new Pair("is_upgraded", bool3));
        ArrayList arrayList = new ArrayList();
        for (Map.Entry entry : mapF.entrySet()) {
            String str = (String) entry.getKey();
            Object value = entry.getValue();
            Pair pair = value != null ? new Pair(str, value) : null;
            if (pair != null) {
                arrayList.add(pair);
            }
        }
        com.snowplowanalytics.snowplow.payload.a aVar2 = new com.snowplowanalytics.snowplow.payload.a("iglu:com.quizlet/user_details/jsonschema/2-0-0", V.k(arrayList));
        com.snowplowanalytics.snowplow.event.f event = new com.snowplowanalytics.snowplow.event.f(aVar);
        event.a.add(aVar2);
        com.snowplowanalytics.core.tracker.o oVar = (com.snowplowanalytics.core.tracker.o) hVar.b;
        if (oVar != null) {
            Intrinsics.checkNotNullParameter(event, "event");
            com.snowplowanalytics.core.tracker.k kVar = (com.snowplowanalytics.core.tracker.k) oVar.b;
            if (kVar.b == null) {
                com.snowplowanalytics.snowplow.tracker.c cVar = com.snowplowanalytics.core.tracker.e.b;
                Intrinsics.checkNotNullExpressionValue("o", "TAG");
                cVar.b("o", "Recreating tracker instance after it was removed. This will not be supported in future versions.");
            }
            kVar.d().c(event);
        }
    }

    public static com.quizlet.data.model.search.c l(SearchBannerWrapper searchBannerWrapper) {
        String str;
        String value;
        String str2;
        String value2 = searchBannerWrapper.a;
        if (value2 == null || (str = searchBannerWrapper.b) == null || (value = searchBannerWrapper.c) == null || (str2 = searchBannerWrapper.d) == null) {
            return null;
        }
        EnumC4497l.Companion.getClass();
        Intrinsics.checkNotNullParameter(value2, "value");
        for (EnumC4497l enumC4497l : EnumC4497l.values()) {
            if (Intrinsics.b(enumC4497l.a(), value2)) {
                W0.Companion.getClass();
                Intrinsics.checkNotNullParameter(value, "value");
                for (W0 w0 : W0.values()) {
                    if (Intrinsics.b(w0.a(), value)) {
                        return new com.quizlet.data.model.search.c(enumC4497l, str, w0, str2);
                    }
                }
                throw new NoSuchElementException("Array contains no element matching the predicate.");
            }
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.d
    public void a() {
        String str = TermListFragment.H;
        ((TermListFragment) this.b).b0().f.A("set_page_term_play_clicked");
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        Object next;
        ArrayList arrayList;
        switch (this.a) {
            case 0:
                Throwable it2 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                BaseSignupFragment baseSignupFragment = (BaseSignupFragment) this.b;
                timber.log.c.a.g(AbstractC0147y.d("Failed to validate during a validate email network request. ", it2.getMessage()), new Object[0]);
                baseSignupFragment.R().setError(baseSignupFragment.getString(R.string.no_network_connection_error_msg));
                return E.a;
            case 1:
            case 3:
            default:
                Object[] objArr = (Object[]) obj;
                if (objArr.length == 2) {
                    return ((io.reactivex.rxjava3.functions.b) this.b).apply(objArr[0], objArr[1]);
                }
                throw new IllegalArgumentException("Array of size 2 expected but got " + objArr.length);
            case 2:
                List errorRequestInfoList = (List) obj;
                Intrinsics.checkNotNullParameter(errorRequestInfoList, "errorRequestInfoList");
                boolean zIsEmpty = errorRequestInfoList.isEmpty();
                Zh zh = (Zh) this.b;
                if (zIsEmpty) {
                    io.reactivex.rxjava3.subjects.r rVar = new io.reactivex.rxjava3.subjects.r();
                    zh.getClass();
                    Intrinsics.checkNotNullParameter(rVar, "<set-?>");
                    zh.o = rVar;
                    com.quizlet.infra.legacysyncengine.datasources.c cVarA = zh.a();
                    com.quizlet.quizletandroid.ui.setcreation.managers.l lVar = (com.quizlet.quizletandroid.ui.setcreation.managers.l) zh.l;
                    if (lVar == null) {
                        Intrinsics.m("studySetListener");
                        throw null;
                    }
                    cVarA.e(lVar);
                    zh.a().d();
                } else {
                    io.reactivex.rxjava3.subjects.d dVar = (io.reactivex.rxjava3.subjects.d) zh.q;
                    com.quizlet.infra.legacysyncengine.net.request.i iVarA = ((com.quizlet.infra.legacysyncengine.net.request.c) errorRequestInfoList.get(0)).a();
                    Intrinsics.checkNotNullExpressionValue(iVarA, "getErrorInfo(...)");
                    dVar.b(new com.quizlet.scandocument.model.v(iVarA));
                }
                return (io.reactivex.rxjava3.subjects.r) zh.o;
            case 4:
                List it3 = (List) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                ((Y) this.b).getClass();
                return it3.isEmpty() ? new ArrayList() : O.b(CollectionsKt.y0(Y.F(Y.G(it3), P.c, null)));
            case 5:
                List<com.quizlet.features.match.highscore.a> scores = (List) obj;
                Intrinsics.checkNotNullParameter(scores, "highScores");
                com.quizlet.features.match.highscore.a other = (com.quizlet.features.match.highscore.a) this.b;
                Intrinsics.checkNotNullParameter(scores, "scores");
                Iterator it4 = scores.iterator();
                while (true) {
                    if (it4.hasNext()) {
                        next = it4.next();
                        if (((com.quizlet.features.match.highscore.a) next).g) {
                        }
                    } else {
                        next = null;
                    }
                }
                com.quizlet.features.match.highscore.a aVar = (com.quizlet.features.match.highscore.a) next;
                if (aVar != null) {
                    Intrinsics.checkNotNullParameter(other, "other");
                    int iH = Intrinsics.h(aVar.b, other.b);
                    if (iH == 0) {
                        iH = Intrinsics.h(aVar.f, other.f);
                    }
                    if (iH <= 0) {
                        return scores;
                    }
                }
                int i = 0;
                if (aVar == null) {
                    ArrayList arrayListY0 = CollectionsKt.y0(scores);
                    arrayListY0.add(other);
                    F.s(arrayListY0);
                    arrayList = new ArrayList(kotlin.collections.C.q(arrayListY0, 10));
                    Iterator it5 = arrayListY0.iterator();
                    while (it5.hasNext()) {
                        Object next2 = it5.next();
                        int i2 = i + 1;
                        if (i < 0) {
                            kotlin.collections.B.p();
                            throw null;
                        }
                        com.quizlet.features.match.highscore.a aVarA = (com.quizlet.features.match.highscore.a) next2;
                        if (aVarA.d != i) {
                            aVarA = com.quizlet.features.match.highscore.a.a(aVarA, i);
                        }
                        arrayList.add(aVarA);
                        i = i2;
                    }
                } else {
                    ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(scores, 10));
                    for (com.quizlet.features.match.highscore.a aVar2 : scores) {
                        if (Intrinsics.b(aVar2, aVar)) {
                            aVar2 = other;
                        }
                        arrayList2.add(aVar2);
                    }
                    List listM0 = CollectionsKt.m0(arrayList2);
                    arrayList = new ArrayList(kotlin.collections.C.q(listM0, 10));
                    for (Object obj2 : listM0) {
                        int i3 = i + 1;
                        if (i < 0) {
                            kotlin.collections.B.p();
                            throw null;
                        }
                        com.quizlet.features.match.highscore.a aVarA2 = (com.quizlet.features.match.highscore.a) obj2;
                        if (aVarA2.d != i) {
                            aVarA2 = com.quizlet.features.match.highscore.a.a(aVarA2, i);
                        }
                        arrayList.add(aVarA2);
                        i = i3;
                    }
                }
                return arrayList;
            case 6:
                Boolean it6 = (Boolean) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                if (it6.booleanValue()) {
                    return (io.reactivex.rxjava3.core.p) this.b;
                }
                io.reactivex.rxjava3.internal.operators.flowable.b bVarF = io.reactivex.rxjava3.core.p.f(Boolean.FALSE);
                Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
                return bVarF;
        }
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.d
    public void b() {
        String str = TermListFragment.H;
        ((TermListFragment) this.b).b0().f.A("set_page_term_star_clicked");
    }

    @Override // com.quizlet.remote.mapper.base.a
    public Object c(Object obj) {
        com.quizlet.remote.model.explanations.search.b remote = (com.quizlet.remote.model.explanations.search.b) obj;
        Intrinsics.checkNotNullParameter(remote, "remote");
        if (!(remote instanceof RemoteTextbook)) {
            if (!(remote instanceof RemoteSearchResultQuestion)) {
                throw new IllegalStateException(remote.getClass() + " is invalid type");
            }
            RemoteSearchResultQuestion remoteSearchResultQuestion = (RemoteSearchResultQuestion) remote;
            long j = remoteSearchResultQuestion.a;
            String str = remoteSearchResultQuestion.h;
            String str2 = str == null ? "" : str;
            List<Integer> list = remoteSearchResultQuestion.e;
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
            for (Integer num : list) {
                com.quizlet.generated.enums.D.Companion.getClass();
                arrayList.add(com.quizlet.generated.enums.C.a(num));
            }
            return new C4154o1(j, remoteSearchResultQuestion.b, remoteSearchResultQuestion.c, remoteSearchResultQuestion.d, arrayList, remoteSearchResultQuestion.f, str2, remoteSearchResultQuestion.g);
        }
        RemoteTextbook remoteTextbook = (RemoteTextbook) remote;
        long j2 = remoteTextbook.a;
        String str3 = remoteTextbook.c;
        String str4 = str3 == null ? "" : str3;
        String str5 = remoteTextbook.d;
        String str6 = str5 == null ? "" : str5;
        String str7 = remoteTextbook.e;
        String str8 = str7 == null ? "" : str7;
        String str9 = remoteTextbook.f;
        String str10 = str9 == null ? "" : str9;
        String str11 = remoteTextbook.g;
        String str12 = str11 == null ? "" : str11;
        Boolean bool = remoteTextbook.h;
        boolean zBooleanValue = bool != null ? bool.booleanValue() : false;
        Boolean bool2 = remoteTextbook.i;
        boolean zBooleanValue2 = bool2 != null ? bool2.booleanValue() : false;
        String str13 = remoteTextbook.j;
        String str14 = str13 == null ? "" : str13;
        Iterable iterable = remoteTextbook.m;
        if (iterable == null) {
            iterable = K.a;
        }
        ArrayList items = new ArrayList(kotlin.collections.C.q(iterable, 10));
        Iterator it2 = iterable.iterator();
        while (it2.hasNext()) {
            items.add(((com.quizlet.data.repository.folderset.c) this.b).c((com.quizlet.remote.model.explanations.toc.a) it2.next()));
        }
        K k = TableOfContents.b;
        Intrinsics.checkNotNullParameter(items, "items");
        return new Textbook(j2, remoteTextbook.b, str4, str8, str12, zBooleanValue, remoteTextbook.l, str6, str10, zBooleanValue2, str14, items);
    }

    public Object d(SerialDescriptor descriptor, kotlinx.serialization.json.internal.l key) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        Intrinsics.checkNotNullParameter(key, "key");
        Map map = (Map) ((ConcurrentHashMap) this.b).get(descriptor);
        Object obj = map != null ? map.get(key) : null;
        if (obj == null) {
            return null;
        }
        return obj;
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        return T.f(this, list);
    }

    @Override // retrofit2.InterfaceC5182g
    public void f(InterfaceC5179d interfaceC5179d, Throwable th) {
        ((C5183h) this.b).completeExceptionally(th);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object g(java.lang.String r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.remote.model.search.b
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.remote.model.search.b r0 = (com.quizlet.remote.model.search.b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.remote.model.search.b r0 = new com.quizlet.remote.model.search.b
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.quizletandroid.ui.login.h r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: java.lang.Exception -> L60
            goto L44
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.Object r6 = r4.b     // Catch: java.lang.Exception -> L60
            com.quizlet.remote.service.y r6 = (com.quizlet.remote.service.y) r6     // Catch: java.lang.Exception -> L60
            r0.j = r4     // Catch: java.lang.Exception -> L60
            r0.m = r3     // Catch: java.lang.Exception -> L60
            java.lang.Object r6 = r6.d(r5, r0)     // Catch: java.lang.Exception -> L60
            if (r6 != r1) goto L43
            return r1
        L43:
            r5 = r4
        L44:
            retrofit2.K r6 = (retrofit2.K) r6     // Catch: java.lang.Exception -> L60
            java.lang.Object r6 = r6.b     // Catch: java.lang.Exception -> L60
            com.quizlet.remote.model.base.ApiThreeWrapper r6 = (com.quizlet.remote.model.base.ApiThreeWrapper) r6     // Catch: java.lang.Exception -> L60
            if (r6 == 0) goto L60
            com.quizlet.remote.model.base.ApiResponse r6 = r6.a()     // Catch: java.lang.Exception -> L60
            com.quizlet.remote.model.search.SearchBannerResponseWrapper r6 = (com.quizlet.remote.model.search.SearchBannerResponseWrapper) r6     // Catch: java.lang.Exception -> L60
            if (r6 == 0) goto L60
            com.quizlet.remote.model.search.SearchBannerWrapper r6 = r6.d     // Catch: java.lang.Exception -> L60
            if (r6 == 0) goto L60
            r5.getClass()     // Catch: java.lang.Exception -> L60
            com.quizlet.data.model.search.c r5 = l(r6)     // Catch: java.lang.Exception -> L60
            return r5
        L60:
            r5 = 0
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.login.h.g(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.quizlet.remote.mapper.base.c
    public Object h(Object obj) {
        Z data = (Z) obj;
        Intrinsics.checkNotNullParameter(data, "data");
        if (data instanceof Textbook) {
            Textbook textbook = (Textbook) data;
            long j = textbook.a;
            Boolean boolValueOf = Boolean.valueOf(textbook.f);
            Boolean boolValueOf2 = Boolean.valueOf(textbook.j);
            List list = textbook.l;
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                arrayList.add(((com.quizlet.data.repository.folderset.c) this.b).h((TableOfContentItem) it2.next()));
            }
            return new RemoteTextbook(j, textbook.b, textbook.c, textbook.h, textbook.d, textbook.i, textbook.e, boolValueOf, boolValueOf2, textbook.k, null, textbook.g, arrayList, false, 9216, null);
        }
        if (!(data instanceof C4154o1)) {
            throw new IllegalStateException(data.getClass() + " is invalid type");
        }
        C4154o1 c4154o1 = (C4154o1) data;
        long j2 = c4154o1.a;
        ArrayList arrayList2 = new ArrayList();
        for (com.quizlet.generated.enums.D d : c4154o1.h) {
            Integer numValueOf = d != null ? Integer.valueOf(d.a()) : null;
            if (numValueOf != null) {
                arrayList2.add(numValueOf);
            }
        }
        return new RemoteSearchResultQuestion(j2, c4154o1.b, c4154o1.c, c4154o1.d, arrayList2, c4154o1.f, c4154o1.g, c4154o1.e);
    }

    public void j() {
        String str = EditSetFragment.J;
        EditSetFragment editSetFragment = (EditSetFragment) this.b;
        com.google.android.gms.internal.appset.e eVar = editSetFragment.r;
        if (eVar == null) {
            Intrinsics.m("scanDocumentManager");
            throw null;
        }
        io.reactivex.rxjava3.internal.observers.e eVarI = ((androidx.work.impl.model.c) eVar.c).q().i(new com.quizlet.quizletandroid.ui.setcreation.fragments.h(editSetFragment, 0), io.reactivex.rxjava3.internal.functions.d.e);
        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
        editSetFragment.G(eVarI);
    }

    @Override // retrofit2.InterfaceC5182g
    public void k(InterfaceC5179d interfaceC5179d, retrofit2.K k) {
        boolean zD = k.a.d();
        C5183h c5183h = (C5183h) this.b;
        if (zD) {
            c5183h.complete(k.b);
        } else {
            c5183h.completeExceptionally(new HttpException(k));
        }
    }

    public h(kotlinx.serialization.json.c json) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(json, "json");
        this.b = json;
    }

    public h(com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c dataSource, com.quizlet.quizletandroid.ui.onboarding.a checkEmailResponseMapper) {
        this.a = 8;
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(checkEmailResponseMapper, "checkEmailResponseMapper");
        this.b = dataSource;
    }

    public h(InterfaceC4779f service) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(service, "service");
        this.b = service;
    }

    public h(com.quizlet.remote.service.y service) {
        this.a = 9;
        Intrinsics.checkNotNullParameter(service, "service");
        this.b = service;
    }

    public h(com.quizlet.data.repository.folderset.c tocMapper) {
        this.a = 7;
        Intrinsics.checkNotNullParameter(tocMapper, "tocMapper");
        this.b = tocMapper;
    }

    public h() {
        this.a = 13;
        this.b = new ConcurrentHashMap(16);
    }
}
