package com.sdk.growthbook.utils;

import androidx.activity.compose.p;
import androidx.compose.material.C0574q;
import androidx.paging.C1319i;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3180j7;
import com.google.android.gms.internal.mlkit_vision_barcode.s7;
import com.google.android.gms.internal.mlkit_vision_camera.P1;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.quizletandroid.interactor.k;
import com.quizlet.quizletandroid.ui.joincontenttofolder.i;
import com.sdk.growthbook.utils.GBUtils;
import io.ktor.client.c;
import io.ktor.client.plugins.AbstractC4863j;
import io.ktor.client.plugins.B;
import io.ktor.client.plugins.C4854a;
import io.ktor.client.plugins.C4856c;
import io.ktor.client.plugins.C4858e;
import io.ktor.client.plugins.C4867n;
import io.ktor.client.plugins.C4869p;
import io.ktor.client.plugins.C4870q;
import io.ktor.client.plugins.C4876x;
import io.ktor.client.plugins.C4878z;
import io.ktor.client.plugins.D;
import io.ktor.client.plugins.J;
import io.ktor.client.plugins.L;
import io.ktor.client.plugins.Y;
import io.ktor.client.plugins.d0;
import io.ktor.client.request.f;
import io.ktor.client.statement.e;
import io.ktor.util.d;
import io.ktor.util.g;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.h;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlinx.coroutines.AbstractC4973a0;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.q0;
import kotlinx.serialization.json.internal.x;
import kotlinx.serialization.json.n;
import okhttp3.A;
import okhttp3.z;
import org.slf4j.b;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        Iterable iterableB;
        int i = 11;
        int i2 = 8;
        int i3 = 3;
        int i4 = 1;
        int i5 = 10;
        int i6 = 9;
        int i7 = 0;
        h hVar = null;
        switch (this.a) {
            case 0:
                return GBUtils.Companion.paddedVersionString$lambda$3((String) obj);
            case 1:
                c install = (c) obj;
                Intrinsics.checkNotNullParameter(install, "$this$install");
                b bVar = AbstractC4863j.a;
                Intrinsics.checkNotNullParameter(install, "<this>");
                install.e.f(f.i, new C0574q(i3, i2, hVar));
                androidx.sqlite.db.a aVar = e.g;
                k kVar = new k(install, null);
                e eVar = install.f;
                eVar.f(aVar, kVar);
                Intrinsics.checkNotNullParameter(install, "<this>");
                eVar.f(aVar, new C0574q(i3, i6, hVar));
                return Unit.a;
            case 2:
                Intrinsics.checkNotNullParameter((io.ktor.client.engine.okhttp.b) obj, "<this>");
                return Unit.a;
            case 3:
                Intrinsics.checkNotNullParameter(obj, "<this>");
                return Unit.a;
            case 4:
                z zVar = (z) obj;
                Intrinsics.checkNotNullParameter(zVar, "<this>");
                zVar.h = false;
                zVar.i = false;
                zVar.f = true;
                return Unit.a;
            case 5:
                Intrinsics.checkNotNullParameter((A) obj, "it");
                return Unit.a;
            case 6:
                io.ktor.client.plugins.api.c createClientPlugin = (io.ktor.client.plugins.api.c) obj;
                Intrinsics.checkNotNullParameter(createClientPlugin, "$this$createClientPlugin");
                createClientPlugin.a(C4854a.c, new p(i3, 6, hVar));
                createClientPlugin.a(C4854a.b, new C4856c(2, null));
                return Unit.a;
            case 7:
                C4867n HttpResponseValidator = (C4867n) obj;
                Intrinsics.checkNotNullParameter(HttpResponseValidator, "$this$HttpResponseValidator");
                HttpResponseValidator.c = false;
                C4858e block = new C4858e(2, null);
                Intrinsics.checkNotNullParameter(block, "block");
                HttpResponseValidator.a.add(block);
                return Unit.a;
            case 8:
                io.ktor.client.plugins.api.c createClientPlugin2 = (io.ktor.client.plugins.api.c) obj;
                Intrinsics.checkNotNullParameter(createClientPlugin2, "$this$createClientPlugin");
                ((d0) createClientPlugin2.b).getClass();
                createClientPlugin2.a.h.f(io.ktor.client.statement.a.f, new C0574q(i3, i5, hVar));
                return Unit.a;
            case 9:
                io.ktor.client.plugins.api.c createClientPlugin3 = (io.ktor.client.plugins.api.c) obj;
                Intrinsics.checkNotNullParameter(createClientPlugin3, "$this$createClientPlugin");
                List listG0 = CollectionsKt.g0(((C4867n) createClientPlugin3.b).a);
                C4867n c4867n = (C4867n) createClientPlugin3.b;
                List listG02 = CollectionsKt.g0(c4867n.b);
                createClientPlugin3.a(io.ktor.client.plugins.api.h.c, new C4869p(c4867n.c, null));
                createClientPlugin3.a(io.ktor.client.plugins.api.h.b, new C1319i(listG0, hVar, i6));
                createClientPlugin3.a(C4854a.f, new C4870q(listG02, hVar, i7));
                createClientPlugin3.a(C4854a.d, new C4870q(listG02, hVar, i4));
                return Unit.a;
            case 10:
                io.ktor.client.plugins.api.c createClientPlugin4 = (io.ktor.client.plugins.api.c) obj;
                Intrinsics.checkNotNullParameter(createClientPlugin4, "$this$createClientPlugin");
                LinkedHashMap linkedHashMap = ((C4876x) createClientPlugin4.b).b;
                Intrinsics.checkNotNullParameter(linkedHashMap, "<this>");
                if (linkedHashMap.size() == 0) {
                    iterableB = K.a;
                } else {
                    Iterator it2 = linkedHashMap.entrySet().iterator();
                    if (it2.hasNext()) {
                        Map.Entry entry = (Map.Entry) it2.next();
                        if (it2.hasNext()) {
                            ArrayList arrayList = new ArrayList(linkedHashMap.size());
                            arrayList.add(new Pair(entry.getKey(), entry.getValue()));
                            do {
                                Map.Entry entry2 = (Map.Entry) it2.next();
                                arrayList.add(new Pair(entry2.getKey(), entry2.getValue()));
                            } while (it2.hasNext());
                            iterableB = arrayList;
                        } else {
                            iterableB = kotlin.collections.A.b(new Pair(entry.getKey(), entry.getValue()));
                        }
                    } else {
                        iterableB = K.a;
                    }
                }
                List<Pair> listN0 = CollectionsKt.n0(iterableB, new B(i4));
                C4876x c4876x = (C4876x) createClientPlugin4.b;
                Charset charset = c4876x.c;
                LinkedHashSet linkedHashSet = c4876x.a;
                ArrayList arrayList2 = new ArrayList();
                for (Object obj2 : linkedHashSet) {
                    if (!c4876x.b.containsKey((Charset) obj2)) {
                        arrayList2.add(obj2);
                    }
                }
                List<Charset> listN02 = CollectionsKt.n0(arrayList2, new B(i7));
                StringBuilder sb = new StringBuilder();
                for (Charset charset2 : listN02) {
                    if (sb.length() > 0) {
                        sb.append(",");
                    }
                    sb.append(s7.d(charset2));
                }
                for (Pair pair : listN0) {
                    Charset charset3 = (Charset) pair.a;
                    float fFloatValue = ((Number) pair.b).floatValue();
                    if (sb.length() > 0) {
                        sb.append(",");
                    }
                    double d = fFloatValue;
                    if (0.0d > d || d > 1.0d) {
                        throw new IllegalStateException("Check failed.");
                    }
                    sb.append(s7.d(charset3) + ";q=" + (kotlin.math.c.b(100 * fFloatValue) / 100.0d));
                }
                if (sb.length() == 0) {
                    sb.append(s7.d(charset));
                }
                String string = sb.toString();
                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                Charset charset4 = (Charset) CollectionsKt.firstOrNull(listN02);
                if (charset4 == null) {
                    Pair pair2 = (Pair) CollectionsKt.firstOrNull(listN0);
                    charset4 = pair2 != null ? (Charset) pair2.a : null;
                    if (charset4 == null) {
                        charset4 = Charsets.UTF_8;
                    }
                }
                createClientPlugin4.a(C4854a.e, new C4878z(string, charset4, null));
                io.ktor.client.plugins.A block2 = new io.ktor.client.plugins.A(charset, null);
                Intrinsics.checkNotNullParameter(block2, "block");
                createClientPlugin4.a(io.ktor.client.plugins.api.h.d, block2);
                return Unit.a;
            case 11:
                io.ktor.client.plugins.api.c createClientPlugin5 = (io.ktor.client.plugins.api.c) obj;
                Intrinsics.checkNotNullParameter(createClientPlugin5, "$this$createClientPlugin");
                ((D) createClientPlugin5.b).getClass();
                ((D) createClientPlugin5.b).getClass();
                createClientPlugin5.a(io.ktor.client.plugins.api.h.b, new C1319i(createClientPlugin5, hVar, i5));
                return Unit.a;
            case 12:
                io.ktor.client.plugins.api.c createClientPlugin6 = (io.ktor.client.plugins.api.c) obj;
                Intrinsics.checkNotNullParameter(createClientPlugin6, "$this$createClientPlugin");
                createClientPlugin6.a(C4854a.g, new C1319i(createClientPlugin6, hVar, i));
                return Unit.a;
            case 13:
                io.ktor.client.plugins.api.c createClientPlugin7 = (io.ktor.client.plugins.api.c) obj;
                Intrinsics.checkNotNullParameter(createClientPlugin7, "$this$createClientPlugin");
                J j = (J) createClientPlugin7.b;
                com.perimeterx.mobile_sdk.api_data.h hVar2 = j.a;
                if (hVar2 == null) {
                    Intrinsics.m("shouldRetry");
                    throw null;
                }
                kotlin.jvm.functions.c cVar = j.b;
                if (cVar == null) {
                    Intrinsics.m("shouldRetryOnException");
                    throw null;
                }
                com.quizlet.features.questiontypes.written.ui.f fVar = j.c;
                if (fVar == null) {
                    Intrinsics.m("delayMillis");
                    throw null;
                }
                createClientPlugin7.a(io.ktor.client.plugins.api.h.b, new L(hVar2, cVar, j.f, fVar, j.d, createClientPlugin7, j.e, null));
                return Unit.a;
            case 14:
                io.ktor.client.plugins.api.c createClientPlugin8 = (io.ktor.client.plugins.api.c) obj;
                Intrinsics.checkNotNullParameter(createClientPlugin8, "$this$createClientPlugin");
                Y y = (Y) createClientPlugin8.b;
                createClientPlugin8.a(io.ktor.client.plugins.api.h.b, new k(y.a, y.b, y.c, null, 2));
                return Unit.a;
            case 15:
                Pair it3 = (Pair) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                String str = (String) it3.a;
                Object obj3 = it3.b;
                if (obj3 == null) {
                    return str;
                }
                return str + '=' + String.valueOf(obj3);
            case 16:
                Map.Entry DelegatingMutableSet = (Map.Entry) obj;
                Intrinsics.checkNotNullParameter(DelegatingMutableSet, "$this$DelegatingMutableSet");
                return new g(((d) DelegatingMutableSet.getKey()).a, DelegatingMutableSet.getValue());
            case 17:
                Map.Entry DelegatingMutableSet2 = (Map.Entry) obj;
                Intrinsics.checkNotNullParameter(DelegatingMutableSet2, "$this$DelegatingMutableSet");
                return new g(AbstractC3180j7.c((String) DelegatingMutableSet2.getKey()), DelegatingMutableSet2.getValue());
            case 18:
                d DelegatingMutableSet3 = (d) obj;
                Intrinsics.checkNotNullParameter(DelegatingMutableSet3, "$this$DelegatingMutableSet");
                return DelegatingMutableSet3.a;
            case 19:
                String DelegatingMutableSet4 = (String) obj;
                Intrinsics.checkNotNullParameter(DelegatingMutableSet4, "$this$DelegatingMutableSet");
                return AbstractC3180j7.c(DelegatingMutableSet4);
            case 20:
                CoroutineContext.Element element = (CoroutineContext.Element) obj;
                if (element instanceof AbstractC5040y) {
                    return (AbstractC5040y) element;
                }
                return null;
            case 21:
                CoroutineContext.Element element2 = (CoroutineContext.Element) obj;
                if (element2 instanceof AbstractC4973a0) {
                    return (AbstractC4973a0) element2;
                }
                return null;
            case EventType.WINDOW_STATE /* 22 */:
                kotlin.reflect.c it4 = (kotlin.reflect.c) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                KSerializer kSerializerG = P1.g(it4);
                if (kSerializerG != null) {
                    return kSerializerG;
                }
                if (AbstractC5047c0.h(it4)) {
                    return new kotlinx.serialization.c(it4);
                }
                return null;
            case EventType.AUDIO /* 23 */:
                kotlin.reflect.c it5 = (kotlin.reflect.c) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                KSerializer kSerializerG2 = P1.g(it5);
                if (kSerializerG2 == null) {
                    kSerializerG2 = AbstractC5047c0.h(it5) ? new kotlinx.serialization.c(it5) : null;
                }
                if (kSerializerG2 != null) {
                    return R1.e(kSerializerG2);
                }
                return null;
            case EventType.VIDEO /* 24 */:
                Intrinsics.checkNotNullParameter((kotlinx.serialization.descriptors.a) obj, "<this>");
                return Unit.a;
            case EventType.SUBS /* 25 */:
                kotlinx.serialization.descriptors.a buildSerialDescriptor = (kotlinx.serialization.descriptors.a) obj;
                Intrinsics.checkNotNullParameter(buildSerialDescriptor, "$this$buildSerialDescriptor");
                kotlinx.serialization.descriptors.a.a(buildSerialDescriptor, "JsonPrimitive", new n(new io.ktor.client.plugins.api.b(7)));
                kotlinx.serialization.descriptors.a.a(buildSerialDescriptor, "JsonNull", new n(new io.ktor.client.plugins.api.b(i2)));
                kotlinx.serialization.descriptors.a.a(buildSerialDescriptor, "JsonLiteral", new n(new io.ktor.client.plugins.api.b(i6)));
                kotlinx.serialization.descriptors.a.a(buildSerialDescriptor, "JsonObject", new n(new io.ktor.client.plugins.api.b(i5)));
                kotlinx.serialization.descriptors.a.a(buildSerialDescriptor, "JsonArray", new n(new io.ktor.client.plugins.api.b(i)));
                return Unit.a;
            case EventType.CDN /* 26 */:
                Map.Entry entry3 = (Map.Entry) obj;
                Intrinsics.checkNotNullParameter(entry3, "<destruct>");
                String str2 = (String) entry3.getKey();
                kotlinx.serialization.json.k kVar2 = (kotlinx.serialization.json.k) entry3.getValue();
                StringBuilder sb2 = new StringBuilder();
                x.a(str2, sb2);
                sb2.append(':');
                sb2.append(kVar2);
                return sb2.toString();
            case 27:
                Intrinsics.checkNotNullParameter((List) obj, "it");
                return q0.a;
            case 28:
                okio.internal.h entry4 = (okio.internal.h) obj;
                Intrinsics.checkNotNullParameter(entry4, "entry");
                okio.x xVar = okio.internal.g.f;
                return Boolean.valueOf(i.a(entry4.a));
            default:
                Intrinsics.checkNotNullParameter((okio.internal.h) obj, "it");
                return Boolean.TRUE;
        }
    }

    public /* synthetic */ a(io.ktor.client.d dVar) {
        this.a = 7;
    }
}
