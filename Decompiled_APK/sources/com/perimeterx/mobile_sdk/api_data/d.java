package com.perimeterx.mobile_sdk.api_data;

import androidx.compose.material.ripple.r;
import com.amazon.device.ads.DtbConstants;
import com.perimeterx.mobile_sdk.PerimeterX;
import io.ktor.http.l;
import io.ktor.http.p;
import io.ktor.http.x;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.U;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class d {
    public final io.ktor.client.c a = i.a;

    /* JADX WARN: Can't wrap try/catch for region: R(11:0|2|(2:4|(1:6)(1:8))(0)|7|9|(1:(1:(2:13|(4:273|293|274|275)(2:291|292))(2:14|15))(1:16))(32:17|18|32|(30:34|(1:36)(1:37)|38|(6:40|(1:42)(1:43)|44|(1:46)(1:47)|48|(2:49|(1:51)(20:298|52|(2:55|53)|299|56|(1:58)(1:59)|60|(1:65)(1:64)|66|(13:68|(2:70|(1:72)(2:73|74))(1:75)|76|(0)|79|(1:81)|82|(1:84)(1:85)|86|(6:88|(1:90)(1:95)|96|(0)|99|(9:101|102|111|(2:113|(1:(1:116)(1:117))(1:118))(1:119)|120|(2:122|(2:124|(1:(2:127|(1:129)(1:130))(1:131))(1:132))(1:133))(1:134)|135|(1:137)|138))|98|99|(0))|78|79|(0)|82|(0)(0)|86|(0)|98|99|(0))))(1:139)|140|(2:143|141)|300|(1:145)(1:146)|147|(1:149)|150|(2:153|151)|301|(1:155)(1:156)|157|(1:159)|160|(2:163|161)|302|164|(2:167|165)|303|168|(1:170)|(1:174)|175|(1:177)|178|(2:181|179)|304)(1:182)|183|(3:187|(1:189)|190)|191|(1:196)(1:195)|197|(1:206)(4:201|(2:204|202)|305|205)|207|(2:210|208)|306|(1:212)(1:213)|214|(1:216)(2:217|(2:(1:220)(1:221)|(1:223)(1:224))(2:225|(2:233|(1:235)(1:236))(1:232)))|237|(1:243)|244|(1:246)|247|(2:250|248)|307|251|(4:254|(2:256|309)(1:310)|257|252)|308|258|(2:261|259)|311|262|(0)|271)|265|295|266|269|(1:(0))) */
    /* JADX WARN: Code restructure failed: missing block: B:268:0x07bc, code lost:
    
        r2 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:270:0x07c9, code lost:
    
        if (r3 == r0) goto L271;
     */
    /* JADX WARN: Removed duplicated region for block: B:101:0x030b  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x0292  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x02aa  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x02b4  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x02cb  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x001e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(com.quizlet.data.interactor.folderwithcreator.m r21, androidx.work.impl.model.n r22, androidx.work.impl.model.i r23, kotlin.coroutines.jvm.internal.c r24) {
        /*
            Method dump skipped, instructions count: 2244
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.api_data.d.a(com.quizlet.data.interactor.folderwithcreator.m, androidx.work.impl.model.n, androidx.work.impl.model.i, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final Object b(String urlString, com.perimeterx.mobile_sdk.configurations.j jVar, final HashMap map, String str, boolean z, kotlin.coroutines.jvm.internal.c cVar) {
        U uC;
        U uC2;
        U uC3;
        final int i = 1;
        Class cls = Long.TYPE;
        int iOrdinal = jVar.ordinal();
        io.ktor.client.c cVar2 = this.a;
        if (iOrdinal == 0) {
            io.ktor.client.request.c cVar3 = new io.ktor.client.request.c();
            int i2 = io.ktor.client.request.e.a;
            Intrinsics.checkNotNullParameter(cVar3, "<this>");
            Intrinsics.checkNotNullParameter(urlString, "urlString");
            x.b(cVar3.a, urlString);
            Function1 block = new Function1() { // from class: com.perimeterx.mobile_sdk.api_data.c
                @Override // kotlin.jvm.functions.Function1
                public final Object invoke(Object obj) {
                    l headers = (l) obj;
                    switch (i) {
                        case 0:
                            Intrinsics.checkNotNullParameter(headers, "$this$headers");
                            for (Map.Entry entry : map.entrySet()) {
                                headers.m((String) entry.getKey(), (String) entry.getValue());
                            }
                            break;
                        default:
                            Intrinsics.checkNotNullParameter(headers, "$this$headers");
                            for (Map.Entry entry2 : map.entrySet()) {
                                headers.m((String) entry2.getKey(), (String) entry2.getValue());
                            }
                            break;
                    }
                    return Unit.a;
                }
            };
            Intrinsics.checkNotNullParameter(cVar3, "<this>");
            Intrinsics.checkNotNullParameter(block, "block");
            block.invoke(cVar3.c);
            p pVar = p.b;
            Intrinsics.checkNotNullParameter(pVar, "<set-?>");
            cVar3.b = pVar;
            return new io.ktor.client.statement.h(cVar3, cVar2).b(cVar);
        }
        if (iOrdinal != 1) {
            throw new NoWhenBranchMatchedException();
        }
        io.ktor.client.request.c cVar4 = new io.ktor.client.request.c();
        int i3 = io.ktor.client.request.e.a;
        Intrinsics.checkNotNullParameter(cVar4, "<this>");
        Intrinsics.checkNotNullParameter(urlString, "urlString");
        x.b(cVar4.a, urlString);
        Intrinsics.d(str);
        U uC4 = null;
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        cVar4.d = str;
        C4950i c4950iA = K.a(Object.class);
        try {
            uC = K.c(Object.class);
        } catch (Throwable unused) {
            uC = null;
        }
        cVar4.a(new io.ktor.util.reflect.a(c4950iA, uC));
        final int i4 = 0;
        Function1 block2 = new Function1() { // from class: com.perimeterx.mobile_sdk.api_data.c
            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                l headers = (l) obj;
                switch (i4) {
                    case 0:
                        Intrinsics.checkNotNullParameter(headers, "$this$headers");
                        for (Map.Entry entry : map.entrySet()) {
                            headers.m((String) entry.getKey(), (String) entry.getValue());
                        }
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(headers, "$this$headers");
                        for (Map.Entry entry2 : map.entrySet()) {
                            headers.m((String) entry2.getKey(), (String) entry2.getValue());
                        }
                        break;
                }
                return Unit.a;
            }
        };
        Intrinsics.checkNotNullParameter(cVar4, "<this>");
        Intrinsics.checkNotNullParameter(block2, "block");
        block2.invoke(cVar4.c);
        if (z) {
            String strA = com.perimeterx.mobile_sdk.configurations.f.a.a();
            C4950i c4950iA2 = K.a(Long.class);
            try {
                uC2 = K.c(cls);
            } catch (Throwable unused2) {
                uC2 = null;
            }
            io.ktor.util.a aVar = new io.ktor.util.a(strA, new io.ktor.util.reflect.a(c4950iA2, uC2));
            Long l = new Long(System.currentTimeMillis());
            io.ktor.util.e eVar = cVar4.f;
            eVar.e(aVar, l);
            String strA2 = com.perimeterx.mobile_sdk.configurations.f.b.a();
            C4950i c4950iA3 = K.a(Long.class);
            try {
                uC3 = K.c(cls);
            } catch (Throwable unused3) {
                uC3 = null;
            }
            eVar.e(new io.ktor.util.a(strA2, new io.ktor.util.reflect.a(c4950iA3, uC3)), new Long(10000L));
            String strA3 = com.perimeterx.mobile_sdk.configurations.f.c.a();
            C4950i c4950iA4 = K.a(Long.class);
            try {
                uC4 = K.c(cls);
            } catch (Throwable unused4) {
            }
            io.ktor.util.a aVar2 = new io.ktor.util.a(strA3, new io.ktor.util.reflect.a(c4950iA4, uC4));
            String str2 = com.perimeterx.mobile_sdk.configurations.i.a;
            eVar.e(aVar2, new Long(300000L));
        }
        p pVar2 = p.c;
        Intrinsics.checkNotNullParameter(pVar2, "<set-?>");
        cVar4.b = pVar2;
        return new io.ktor.client.statement.h(cVar4, cVar2).b(cVar);
    }

    public final Object c(String appId, String str, boolean z, com.perimeterx.mobile_sdk.detections.device.a aVar, r rVar, kotlin.coroutines.jvm.internal.i iVar) throws JSONException, UnsupportedEncodingException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.putOpt(com.perimeterx.mobile_sdk.configurations.b.k1.a(), str);
        jSONObject.putOpt(com.perimeterx.mobile_sdk.configurations.b.l1.a(), (z ? com.perimeterx.mobile_sdk.configurations.b.b : com.perimeterx.mobile_sdk.configurations.b.c).a());
        String strA = com.perimeterx.mobile_sdk.configurations.b.e.a();
        PerimeterX perimeterX = PerimeterX.INSTANCE;
        Intrinsics.checkNotNullParameter(perimeterX, "<this>");
        StringBuilder sb = new StringBuilder();
        com.perimeterx.mobile_sdk.configurations.h hVar = com.perimeterx.mobile_sdk.configurations.h.e;
        sb.append(hVar.a());
        sb.append(perimeterX.sdkVersion());
        jSONObject.putOpt(strA, sb.toString());
        jSONObject.putOpt(com.perimeterx.mobile_sdk.configurations.b.j.a(), appId);
        jSONObject.putOpt(com.perimeterx.mobile_sdk.configurations.b.v.a(), (String) rVar.e);
        jSONObject.putOpt(com.perimeterx.mobile_sdk.configurations.b.w.a(), aVar.l);
        jSONObject.putOpt(com.perimeterx.mobile_sdk.configurations.b.t.a(), aVar.i);
        jSONObject.putOpt(com.perimeterx.mobile_sdk.configurations.b.u.a(), com.perimeterx.mobile_sdk.configurations.b.n.a());
        String string = jSONObject.toString();
        com.perimeterx.mobile_sdk.configurations.d[] dVarArr = com.perimeterx.mobile_sdk.configurations.d.a;
        if (com.perimeterx.mobile_sdk.configurations.c.a[0] != 1) {
            throw new NoWhenBranchMatchedException();
        }
        String strEncode = URLEncoder.encode(string, "UTF-8");
        StringBuilder sb2 = new StringBuilder();
        Intrinsics.checkNotNullParameter(appId, "appId");
        StringBuilder sb3 = new StringBuilder(DtbConstants.HTTPS);
        String str2 = com.perimeterx.mobile_sdk.configurations.i.a;
        Intrinsics.checkNotNullParameter(appId, "appId");
        sb3.append(com.perimeterx.mobile_sdk.configurations.i.a("collector-%@.", appId));
        sb3.append("perimeterx.net/api/v1/collector/clientError");
        com.perimeterx.mobile_sdk.configurations.a[] aVarArr = com.perimeterx.mobile_sdk.configurations.a.a;
        sb2.append(sb3.toString());
        sb2.append(com.perimeterx.mobile_sdk.configurations.l.a.a());
        sb2.append(com.perimeterx.mobile_sdk.configurations.b.q.a());
        sb2.append("=0");
        sb2.append(com.perimeterx.mobile_sdk.configurations.l.b.a());
        sb2.append(com.perimeterx.mobile_sdk.configurations.b.r.a());
        sb2.append('=');
        sb2.append(strEncode);
        String string2 = sb2.toString();
        HashMap map = new HashMap();
        HashMap map2 = new HashMap();
        String strA2 = com.perimeterx.mobile_sdk.configurations.g.b.a();
        Intrinsics.checkNotNullParameter(perimeterX, "<this>");
        map2.put(strA2, hVar.a() + perimeterX.sdkVersion());
        for (Map.Entry entry : map2.entrySet()) {
            map.put((String) entry.getKey(), (String) entry.getValue());
        }
        Object objB = b(string2, com.perimeterx.mobile_sdk.configurations.j.a, map, null, false, iVar);
        return objB == kotlin.coroutines.intrinsics.a.a ? objB : Unit.a;
    }
}
