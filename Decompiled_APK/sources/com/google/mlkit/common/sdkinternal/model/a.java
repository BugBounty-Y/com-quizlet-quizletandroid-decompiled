package com.google.mlkit.common.sdkinternal.model;

import androidx.camera.camera2.internal.c0;
import androidx.camera.camera2.internal.compat.quirk.UseTorchAsFlashQuirk;
import androidx.camera.core.impl.i0;
import androidx.camera.core.impl.utils.executor.i;
import androidx.compose.animation.core.AbstractC0267t;
import androidx.compose.animation.core.P0;
import androidx.lifecycle.A0;
import androidx.lifecycle.C0;
import androidx.lifecycle.InterfaceC1261w;
import androidx.lifecycle.y0;
import com.bumptech.glide.util.pool.c;
import com.facebook.internal.A;
import com.facebook.o;
import com.facebook.y;
import com.google.android.gms.internal.measurement.C2991f3;
import com.google.android.gms.internal.measurement.O2;
import com.google.android.gms.internal.measurement.Q2;
import com.google.android.gms.internal.measurement.W3;
import com.google.android.gms.internal.measurement.Y3;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.google.android.gms.measurement.internal.r;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.e;
import com.google.firebase.components.d;
import com.google.firebase.perf.network.FirebasePerfUrlConnection;
import com.google.gson.internal.n;
import com.google.mlkit.common.sdkinternal.f;
import com.perimeterx.mobile_sdk.configurations.k;
import com.perimeterx.mobile_sdk.session.m;
import com.quizlet.data.interactor.achievements.g;
import com.quizlet.data.model.AbstractC4163s;
import com.quizlet.data.model.C4121d2;
import com.quizlet.data.model.C4155p;
import com.quizlet.data.model.h2;
import com.quizlet.features.achievements.achievement.h;
import com.quizlet.features.achievements.achievement.j;
import com.quizlet.features.achievements.achievement.l;
import com.quizlet.generated.enums.EnumC4479f;
import io.reactivex.rxjava3.functions.b;
import java.io.File;
import java.io.IOException;
import java.net.HttpCookie;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.chrono.ChronoLocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.C;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.collections.U;
import kotlin.collections.b0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.D;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class a implements P0, com.bumptech.glide.load.engine.cache.a, c, r, e, n, d, b {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    public static com.perimeterx.mobile_sdk.block.b e(String response) {
        Intrinsics.checkNotNullParameter(response, "response");
        try {
            com.perimeterx.mobile_sdk.block.b bVar = new com.perimeterx.mobile_sdk.block.b(new JSONObject(response));
            if (bVar.a() != null) {
                return bVar;
            }
            return null;
        } catch (Exception unused) {
            return null;
        }
    }

    public static String h(m session, com.perimeterx.mobile_sdk.detections.device.a deviceInfo) throws JSONException {
        Intrinsics.checkNotNullParameter(session, "session");
        Intrinsics.checkNotNullParameter(deviceInfo, "deviceInfo");
        try {
            JSONObject jSONObject = new JSONObject();
            jSONObject.putOpt("mobile_device_fp", deviceInfo.a);
            Base64.Encoder encoder = Base64.getEncoder();
            String string = jSONObject.toString();
            Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
            byte[] bytes = string.getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
            String strEncodeToString = encoder.encodeToString(bytes);
            Intrinsics.d(strEncodeToString);
            return strEncodeToString;
        } catch (Exception unused) {
            return "";
        }
    }

    public static String i(String str, String str2) {
        int i;
        int i2 = 3;
        Charset charset = Charsets.UTF_8;
        byte[] a = str.getBytes(charset);
        Intrinsics.checkNotNullExpressionValue(a, "getBytes(...)");
        byte[] b = str2.getBytes(charset);
        Intrinsics.checkNotNullExpressionValue(b, "getBytes(...)");
        Intrinsics.checkNotNullParameter(a, "a");
        Intrinsics.checkNotNullParameter(b, "b");
        int length = a.length;
        byte[] bArr = new byte[length];
        for (int i3 = 0; i3 < length; i3++) {
            bArr[i3] = (byte) (a[i3] ^ b[i3 % b.length]);
        }
        int i4 = io.ktor.util.b.a;
        Intrinsics.checkNotNullParameter(bArr, "<this>");
        char[] cArr = new char[((length * 8) / 6) + 3];
        int i5 = 0;
        int i6 = 0;
        while (true) {
            int i7 = i5 + 3;
            if (i7 > length) {
                break;
            }
            int i8 = (bArr[i5 + 2] & 255) | ((bArr[i5] & 255) << 16) | ((bArr[i5 + 1] & 255) << 8);
            int i9 = 3;
            while (-1 < i9) {
                cArr[i6] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt((i8 >> (i9 * 6)) & 63);
                i9--;
                i6++;
            }
            i5 = i7;
        }
        int i10 = length - i5;
        if (i10 == 0) {
            return D.h(cArr, 0, i6);
        }
        int i11 = i10 == 1 ? (bArr[i5] & 255) << 16 : ((bArr[i5 + 1] & 255) << 8) | ((bArr[i5] & 255) << 16);
        int i12 = ((3 - i10) * 8) / 6;
        if (i12 <= 3) {
            while (true) {
                i = i6 + 1;
                cArr[i6] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt((i11 >> (i2 * 6)) & 63);
                if (i2 == i12) {
                    break;
                }
                i2--;
                i6 = i;
            }
            i6 = i;
        }
        int i13 = 0;
        while (i13 < i12) {
            cArr[i6] = '=';
            i13++;
            i6++;
        }
        return D.h(cArr, 0, i6);
    }

    public static HttpCookie l(String str, String str2, String str3) {
        String host = new URL(str).getHost();
        Intrinsics.checkNotNullExpressionValue(host, "getHost(...)");
        k[] kVarArr = k.a;
        String strO = D.o(host, "www".concat("."), ".", false);
        HttpCookie httpCookie = new HttpCookie(str2, str3);
        httpCookie.setVersion(0);
        httpCookie.setPath("/");
        httpCookie.setDomain(strO);
        return httpCookie;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static LinkedHashMap o(HashMap map, HashMap map2) {
        Set setKeySet = map.keySet();
        Intrinsics.checkNotNullExpressionValue(setKeySet, "<get-keys>(...)");
        Set setKeySet2 = map2.keySet();
        Intrinsics.checkNotNullExpressionValue(setKeySet2, "<get-keys>(...)");
        LinkedHashSet linkedHashSetF = b0.f(setKeySet, setKeySet2);
        int iA = U.a(C.q(linkedHashSetF, 10));
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
        for (Object obj : linkedHashSetF) {
            String str = (String) obj;
            String[] elements = {map.get(str), map2.get(str)};
            Intrinsics.checkNotNullParameter(elements, "elements");
            linkedHashMap.put(obj, CollectionsKt.S(CollectionsKt.J(C4933y.T(elements)), null, null, null, null, 63));
        }
        return linkedHashMap;
    }

    public static A0 p(C0 owner, y0 factory, int i) {
        if ((i & 2) != 0) {
            Intrinsics.checkNotNullParameter(owner, "owner");
            factory = owner instanceof InterfaceC1261w ? ((InterfaceC1261w) owner).getDefaultViewModelProviderFactory() : androidx.lifecycle.viewmodel.internal.b.a;
        }
        Intrinsics.checkNotNullParameter(owner, "owner");
        androidx.lifecycle.viewmodel.c extras = owner instanceof InterfaceC1261w ? ((InterfaceC1261w) owner).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b;
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(extras, "extras");
        return new A0(owner.getViewModelStore(), factory, extras);
    }

    public static com.airbnb.lottie.network.a q(String str) throws IOException {
        HttpURLConnection httpURLConnection = (HttpURLConnection) ((URLConnection) FirebasePerfUrlConnection.instrument(new URL(str).openConnection()));
        httpURLConnection.setRequestMethod("GET");
        httpURLConnection.connect();
        return new com.airbnb.lottie.network.a(httpURLConnection);
    }

    public static com.quizlet.ads.c r(int i) {
        for (com.quizlet.ads.c cVar : com.quizlet.ads.c.values()) {
            if (cVar.a == i) {
                return cVar;
            }
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }

    public static androidx.camera.core.impl.utils.e s(g achievementsStreak) {
        Intrinsics.checkNotNullParameter(achievementsStreak, "achievementsStreak");
        AbstractC4163s abstractC4163s = achievementsStreak.c;
        C4155p c4155p = abstractC4163s instanceof C4155p ? (C4155p) abstractC4163s : null;
        h2 h2Var = achievementsStreak.b;
        C4121d2 c4121d2 = h2Var instanceof C4121d2 ? (C4121d2) h2Var : null;
        if (c4155p == null || c4121d2 == null) {
            return null;
        }
        int[] iArr = com.quizlet.features.achievements.achievement.k.a;
        EnumC4479f enumC4479f = c4121d2.a;
        int i = iArr[enumC4479f.ordinal()];
        String str = c4121d2.h;
        String str2 = c4121d2.g;
        String str3 = c4121d2.f;
        switch (i) {
            case 1:
            case 2:
            case 3:
            case 4:
                LocalDate localDateNow = LocalDate.now();
                Intrinsics.checkNotNullExpressionValue(localDateNow, "now(...)");
                ArrayList arrayList = c4155p.a;
                ArrayList arrayList2 = new ArrayList(C.q(arrayList, 10));
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    arrayList2.add(((LocalDateTime) it2.next()).toLocalDate());
                }
                ArrayList arrayList3 = new ArrayList();
                DayOfWeek dayOfWeek = localDateNow.getDayOfWeek();
                Intrinsics.checkNotNullExpressionValue(dayOfWeek, "getDayOfWeek(...)");
                int iB = i.b(dayOfWeek);
                int i2 = 1;
                if (1 <= iB) {
                    int i3 = 1;
                    while (true) {
                        Intrinsics.checkNotNullExpressionValue(localDateNow.getDayOfWeek(), "getDayOfWeek(...)");
                        LocalDate localDateMinusDays = localDateNow.minusDays(Math.abs(i3 - i.b(r13)));
                        arrayList3.add(new l(localDateMinusDays.getDayOfMonth(), localDateMinusDays.equals(localDateNow), i.c(localDateMinusDays, arrayList2)));
                        if (i3 != iB) {
                            i3++;
                        }
                    }
                }
                int iB2 = i.b(DayOfWeek.SATURDAY);
                DayOfWeek dayOfWeek2 = localDateNow.getDayOfWeek();
                Intrinsics.checkNotNullExpressionValue(dayOfWeek2, "getDayOfWeek(...)");
                int iB3 = iB2 - i.b(dayOfWeek2);
                if (1 <= iB3) {
                    while (true) {
                        LocalDate localDatePlusDays = localDateNow.plusDays(i2);
                        arrayList3.add(new l(localDatePlusDays.getDayOfMonth(), false, i.c(localDatePlusDays, arrayList2)));
                        if (i2 != iB3) {
                            i2++;
                        }
                    }
                }
                LocalDateTime localDateTimeNow = LocalDateTime.now();
                Intrinsics.checkNotNullExpressionValue(localDateTimeNow, "now(...)");
                if (c4121d2.e.compareTo((ChronoLocalDateTime<?>) localDateTimeNow) > 0) {
                    return new com.quizlet.features.achievements.achievement.i(c4121d2.b, str3, str2, str, AbstractC3409x1.i(arrayList3));
                }
                return new h(str3, str2, str, AbstractC3409x1.i(arrayList3));
            case 5:
                return new j(str3, str2, str);
            case 6:
            case 7:
            case 8:
            case 9:
                throw new IllegalArgumentException("Unexpected achievements type: " + enumC4479f);
            default:
                throw new NoWhenBranchMatchedException();
        }
    }

    public static void v(y behavior, String tag, String string) {
        Intrinsics.checkNotNullParameter(behavior, "behavior");
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(string, "string");
        x(behavior, tag, string);
    }

    public static void w(y behavior, String tag, String format, Object... args) {
        Intrinsics.checkNotNullParameter(behavior, "behavior");
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(format, "format");
        Intrinsics.checkNotNullParameter(args, "args");
        o.h(behavior);
    }

    public static void x(y behavior, String tag, String string) {
        Intrinsics.checkNotNullParameter(behavior, "behavior");
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(string, "string");
        o.h(behavior);
    }

    @Override // com.google.gson.internal.n
    public Object E() {
        return new LinkedHashSet();
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object t, Object u) {
        Intrinsics.checkNotNullExpressionValue(t, "t");
        Intrinsics.checkNotNullExpressionValue(u, "u");
        List list = (List) u;
        List list2 = (List) t;
        Intrinsics.d(list2);
        Intrinsics.d(list);
        return CollectionsKt.c0(list2, list);
    }

    @Override // com.bumptech.glide.load.engine.cache.a
    public File c(com.bumptech.glide.load.e eVar) {
        return null;
    }

    @Override // com.bumptech.glide.load.engine.cache.a
    public void d(com.bumptech.glide.load.e eVar, com.quizlet.data.repository.login.a aVar) {
    }

    @Override // com.google.firebase.components.d
    public Object f(c0 c0Var) {
        return new com.google.mlkit.vision.barcode.internal.d((f) c0Var.get(f.class));
    }

    @Override // com.google.android.gms.tasks.e
    public Task g(Object obj) {
        return S3.i(Boolean.TRUE);
    }

    @Override // androidx.compose.animation.core.N0
    public AbstractC0267t j(long j, AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        return abstractC0267t3;
    }

    @Override // com.bumptech.glide.util.pool.c
    public void k(Object obj) {
    }

    @Override // androidx.compose.animation.core.P0
    public int m() {
        return 0;
    }

    @Override // androidx.compose.animation.core.N0
    public AbstractC0267t t(long j, AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        return j < ((long) 0) * 1000000 ? abstractC0267t : abstractC0267t2;
    }

    @Override // androidx.compose.animation.core.P0
    public int u() {
        return 0;
    }

    public synchronized void y(String original) {
        Intrinsics.checkNotNullParameter(original, "accessToken");
        o.h(y.b);
        synchronized (this) {
            Intrinsics.checkNotNullParameter(original, "original");
            Intrinsics.checkNotNullParameter("ACCESS_TOKEN_REMOVED", "replace");
            A.d.put(original, "ACCESS_TOKEN_REMOVED");
        }
    }

    @Override // com.google.android.gms.measurement.internal.r
    public Object zza() {
        switch (this.a) {
            case 10:
                List list = AbstractC3893t.a;
                Boolean bool = (Boolean) C2991f3.c.b();
                bool.getClass();
                return bool;
            case 11:
                List list2 = AbstractC3893t.a;
                W3.b.get();
                Boolean bool2 = (Boolean) Y3.b.b();
                bool2.getClass();
                return bool2;
            case 12:
                List list3 = AbstractC3893t.a;
                O2.b.get();
                Long l = (Long) Q2.a.b();
                l.getClass();
                return l;
            case 13:
                List list4 = AbstractC3893t.a;
                O2.b.get();
                return (String) Q2.J.b();
            case 14:
                List list5 = AbstractC3893t.a;
                O2.b.get();
                Long l2 = (Long) Q2.s0.b();
                l2.getClass();
                return l2;
            case 15:
                List list6 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.m.b()).longValue());
            case 16:
                List list7 = AbstractC3893t.a;
                O2.b.get();
                Long l3 = (Long) Q2.a0.b();
                l3.getClass();
                return l3;
            default:
                List list8 = AbstractC3893t.a;
                O2.b.get();
                Long l4 = (Long) Q2.W.b();
                l4.getClass();
                return l4;
        }
    }

    public a(i0 i0Var) {
        this.a = 1;
        i0Var.a(UseTorchAsFlashQuirk.class);
    }
}
