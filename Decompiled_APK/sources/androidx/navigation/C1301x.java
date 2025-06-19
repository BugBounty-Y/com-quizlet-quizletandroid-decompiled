package androidx.navigation;

import android.net.Uri;
import android.os.Bundle;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3335e2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3343g2;
import com.google.android.gms.internal.mlkit_vision_camera.E1;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.MatchGroup;
import kotlin.text.Regex;
import kotlin.text.StringsKt;

/* renamed from: androidx.navigation.x, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1301x {
    public static final Regex m = new Regex("^[a-zA-Z]+[+\\w\\-.]*:");
    public static final Regex n = new Regex("\\{(.+?)\\}");
    public static final Regex o = new Regex("http[s]?://");
    public static final Regex p = new Regex(".*");
    public static final Regex q = new Regex("([^/]*?|)");
    public static final Regex r = new Regex("^[^?#]+\\?([^#]*).*");
    public final String a;
    public final ArrayList b;
    public final String c;
    public final kotlin.u d;
    public final kotlin.u e;
    public final Object f;
    public boolean g;
    public final Object h;
    public final Object i;
    public final Object j;
    public final kotlin.u k;
    public final boolean l;

    public C1301x(String str) {
        this.a = str;
        ArrayList arrayList = new ArrayList();
        this.b = arrayList;
        final int i = 0;
        this.d = kotlin.l.b(new Function0(this) { // from class: androidx.navigation.u
            public final /* synthetic */ C1301x b;

            {
                this.b = this;
            }

            /* JADX WARN: Type inference failed for: r0v20, types: [java.lang.Object, kotlin.k] */
            /* JADX WARN: Type inference failed for: r0v27, types: [java.lang.Object, kotlin.k] */
            /* JADX WARN: Type inference failed for: r0v34, types: [java.lang.Object, kotlin.k] */
            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                List list;
                switch (i) {
                    case 0:
                        String str2 = this.b.c;
                        if (str2 != null) {
                            return new Regex(str2, kotlin.text.s.b);
                        }
                        return null;
                    case 1:
                        String str3 = this.b.a;
                        return Boolean.valueOf(str3 != null && C1301x.r.e(str3));
                    case 2:
                        C1301x c1301x = this.b;
                        c1301x.getClass();
                        LinkedHashMap linkedHashMap = new LinkedHashMap();
                        if (((Boolean) c1301x.e.getValue()).booleanValue()) {
                            String uriString = c1301x.a;
                            Intrinsics.d(uriString);
                            Intrinsics.checkNotNullParameter(uriString, "uriString");
                            Uri uri = Uri.parse(uriString);
                            Intrinsics.checkNotNullExpressionValue(uri, "parse(...)");
                            for (String str4 : uri.getQueryParameterNames()) {
                                StringBuilder sb = new StringBuilder();
                                List<String> queryParameters = uri.getQueryParameters(str4);
                                if (queryParameters.size() > 1) {
                                    throw new IllegalArgumentException(AbstractC0147y.e("Query parameter ", str4, " must only be present once in ", uriString, ". To support repeated query parameters, use an array type for your argument and the pattern provided in your URI will be used to parse each query parameter instance.").toString());
                                }
                                String str5 = (String) CollectionsKt.firstOrNull(queryParameters);
                                if (str5 == null) {
                                    c1301x.g = true;
                                    str5 = str4;
                                }
                                C1300w c1300w = new C1300w();
                                int i2 = 0;
                                for (kotlin.text.m mVarB = C1301x.n.b(str5); mVarB != null; mVarB = mVarB.next()) {
                                    MatchGroup matchGroupB = mVarB.c.b(1);
                                    Intrinsics.d(matchGroupB);
                                    String name = matchGroupB.a;
                                    Intrinsics.checkNotNullParameter(name, "name");
                                    c1300w.b.add(name);
                                    if (mVarB.c().a > i2) {
                                        String strSubstring = str5.substring(i2, mVarB.c().a);
                                        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                                        Regex.b.getClass();
                                        sb.append(kotlin.text.n.a(strSubstring));
                                    }
                                    sb.append("([\\s\\S]+?)?");
                                    i2 = mVarB.c().b + 1;
                                }
                                if (i2 < str5.length()) {
                                    kotlin.text.n nVar = Regex.b;
                                    String strSubstring2 = str5.substring(i2);
                                    Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                                    nVar.getClass();
                                    sb.append(kotlin.text.n.a(strSubstring2));
                                }
                                sb.append("$");
                                String string = sb.toString();
                                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                                c1300w.a = C1301x.i(string);
                                linkedHashMap.put(str4, c1300w);
                            }
                        }
                        return linkedHashMap;
                    case 3:
                        String uriString2 = this.b.a;
                        if (uriString2 != null) {
                            Intrinsics.checkNotNullParameter(uriString2, "uriString");
                            Uri uri2 = Uri.parse(uriString2);
                            Intrinsics.checkNotNullExpressionValue(uri2, "parse(...)");
                            if (uri2.getFragment() != null) {
                                ArrayList arrayList2 = new ArrayList();
                                Intrinsics.checkNotNullParameter(uriString2, "uriString");
                                Uri uri3 = Uri.parse(uriString2);
                                Intrinsics.checkNotNullExpressionValue(uri3, "parse(...)");
                                String fragment = uri3.getFragment();
                                StringBuilder sb2 = new StringBuilder();
                                Intrinsics.d(fragment);
                                C1301x.a(fragment, sb2, arrayList2);
                                return new Pair(arrayList2, sb2.toString());
                            }
                        }
                        return null;
                    case 4:
                        Pair pair = (Pair) this.b.h.getValue();
                        return (pair == null || (list = (List) pair.a) == null) ? new ArrayList() : list;
                    case 5:
                        Pair pair2 = (Pair) this.b.h.getValue();
                        if (pair2 != null) {
                            return (String) pair2.b;
                        }
                        return null;
                    case 6:
                        String str6 = (String) this.b.j.getValue();
                        if (str6 != null) {
                            return new Regex(str6, kotlin.text.s.b);
                        }
                        return null;
                    default:
                        this.b.getClass();
                        return null;
                }
            }
        });
        final int i2 = 1;
        this.e = kotlin.l.b(new Function0(this) { // from class: androidx.navigation.u
            public final /* synthetic */ C1301x b;

            {
                this.b = this;
            }

            /* JADX WARN: Type inference failed for: r0v20, types: [java.lang.Object, kotlin.k] */
            /* JADX WARN: Type inference failed for: r0v27, types: [java.lang.Object, kotlin.k] */
            /* JADX WARN: Type inference failed for: r0v34, types: [java.lang.Object, kotlin.k] */
            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                List list;
                switch (i2) {
                    case 0:
                        String str2 = this.b.c;
                        if (str2 != null) {
                            return new Regex(str2, kotlin.text.s.b);
                        }
                        return null;
                    case 1:
                        String str3 = this.b.a;
                        return Boolean.valueOf(str3 != null && C1301x.r.e(str3));
                    case 2:
                        C1301x c1301x = this.b;
                        c1301x.getClass();
                        LinkedHashMap linkedHashMap = new LinkedHashMap();
                        if (((Boolean) c1301x.e.getValue()).booleanValue()) {
                            String uriString = c1301x.a;
                            Intrinsics.d(uriString);
                            Intrinsics.checkNotNullParameter(uriString, "uriString");
                            Uri uri = Uri.parse(uriString);
                            Intrinsics.checkNotNullExpressionValue(uri, "parse(...)");
                            for (String str4 : uri.getQueryParameterNames()) {
                                StringBuilder sb = new StringBuilder();
                                List<String> queryParameters = uri.getQueryParameters(str4);
                                if (queryParameters.size() > 1) {
                                    throw new IllegalArgumentException(AbstractC0147y.e("Query parameter ", str4, " must only be present once in ", uriString, ". To support repeated query parameters, use an array type for your argument and the pattern provided in your URI will be used to parse each query parameter instance.").toString());
                                }
                                String str5 = (String) CollectionsKt.firstOrNull(queryParameters);
                                if (str5 == null) {
                                    c1301x.g = true;
                                    str5 = str4;
                                }
                                C1300w c1300w = new C1300w();
                                int i22 = 0;
                                for (kotlin.text.m mVarB = C1301x.n.b(str5); mVarB != null; mVarB = mVarB.next()) {
                                    MatchGroup matchGroupB = mVarB.c.b(1);
                                    Intrinsics.d(matchGroupB);
                                    String name = matchGroupB.a;
                                    Intrinsics.checkNotNullParameter(name, "name");
                                    c1300w.b.add(name);
                                    if (mVarB.c().a > i22) {
                                        String strSubstring = str5.substring(i22, mVarB.c().a);
                                        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                                        Regex.b.getClass();
                                        sb.append(kotlin.text.n.a(strSubstring));
                                    }
                                    sb.append("([\\s\\S]+?)?");
                                    i22 = mVarB.c().b + 1;
                                }
                                if (i22 < str5.length()) {
                                    kotlin.text.n nVar = Regex.b;
                                    String strSubstring2 = str5.substring(i22);
                                    Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                                    nVar.getClass();
                                    sb.append(kotlin.text.n.a(strSubstring2));
                                }
                                sb.append("$");
                                String string = sb.toString();
                                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                                c1300w.a = C1301x.i(string);
                                linkedHashMap.put(str4, c1300w);
                            }
                        }
                        return linkedHashMap;
                    case 3:
                        String uriString2 = this.b.a;
                        if (uriString2 != null) {
                            Intrinsics.checkNotNullParameter(uriString2, "uriString");
                            Uri uri2 = Uri.parse(uriString2);
                            Intrinsics.checkNotNullExpressionValue(uri2, "parse(...)");
                            if (uri2.getFragment() != null) {
                                ArrayList arrayList2 = new ArrayList();
                                Intrinsics.checkNotNullParameter(uriString2, "uriString");
                                Uri uri3 = Uri.parse(uriString2);
                                Intrinsics.checkNotNullExpressionValue(uri3, "parse(...)");
                                String fragment = uri3.getFragment();
                                StringBuilder sb2 = new StringBuilder();
                                Intrinsics.d(fragment);
                                C1301x.a(fragment, sb2, arrayList2);
                                return new Pair(arrayList2, sb2.toString());
                            }
                        }
                        return null;
                    case 4:
                        Pair pair = (Pair) this.b.h.getValue();
                        return (pair == null || (list = (List) pair.a) == null) ? new ArrayList() : list;
                    case 5:
                        Pair pair2 = (Pair) this.b.h.getValue();
                        if (pair2 != null) {
                            return (String) pair2.b;
                        }
                        return null;
                    case 6:
                        String str6 = (String) this.b.j.getValue();
                        if (str6 != null) {
                            return new Regex(str6, kotlin.text.s.b);
                        }
                        return null;
                    default:
                        this.b.getClass();
                        return null;
                }
            }
        });
        kotlin.m mVar = kotlin.m.c;
        final int i3 = 2;
        this.f = kotlin.l.a(mVar, new Function0(this) { // from class: androidx.navigation.u
            public final /* synthetic */ C1301x b;

            {
                this.b = this;
            }

            /* JADX WARN: Type inference failed for: r0v20, types: [java.lang.Object, kotlin.k] */
            /* JADX WARN: Type inference failed for: r0v27, types: [java.lang.Object, kotlin.k] */
            /* JADX WARN: Type inference failed for: r0v34, types: [java.lang.Object, kotlin.k] */
            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                List list;
                switch (i3) {
                    case 0:
                        String str2 = this.b.c;
                        if (str2 != null) {
                            return new Regex(str2, kotlin.text.s.b);
                        }
                        return null;
                    case 1:
                        String str3 = this.b.a;
                        return Boolean.valueOf(str3 != null && C1301x.r.e(str3));
                    case 2:
                        C1301x c1301x = this.b;
                        c1301x.getClass();
                        LinkedHashMap linkedHashMap = new LinkedHashMap();
                        if (((Boolean) c1301x.e.getValue()).booleanValue()) {
                            String uriString = c1301x.a;
                            Intrinsics.d(uriString);
                            Intrinsics.checkNotNullParameter(uriString, "uriString");
                            Uri uri = Uri.parse(uriString);
                            Intrinsics.checkNotNullExpressionValue(uri, "parse(...)");
                            for (String str4 : uri.getQueryParameterNames()) {
                                StringBuilder sb = new StringBuilder();
                                List<String> queryParameters = uri.getQueryParameters(str4);
                                if (queryParameters.size() > 1) {
                                    throw new IllegalArgumentException(AbstractC0147y.e("Query parameter ", str4, " must only be present once in ", uriString, ". To support repeated query parameters, use an array type for your argument and the pattern provided in your URI will be used to parse each query parameter instance.").toString());
                                }
                                String str5 = (String) CollectionsKt.firstOrNull(queryParameters);
                                if (str5 == null) {
                                    c1301x.g = true;
                                    str5 = str4;
                                }
                                C1300w c1300w = new C1300w();
                                int i22 = 0;
                                for (kotlin.text.m mVarB = C1301x.n.b(str5); mVarB != null; mVarB = mVarB.next()) {
                                    MatchGroup matchGroupB = mVarB.c.b(1);
                                    Intrinsics.d(matchGroupB);
                                    String name = matchGroupB.a;
                                    Intrinsics.checkNotNullParameter(name, "name");
                                    c1300w.b.add(name);
                                    if (mVarB.c().a > i22) {
                                        String strSubstring = str5.substring(i22, mVarB.c().a);
                                        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                                        Regex.b.getClass();
                                        sb.append(kotlin.text.n.a(strSubstring));
                                    }
                                    sb.append("([\\s\\S]+?)?");
                                    i22 = mVarB.c().b + 1;
                                }
                                if (i22 < str5.length()) {
                                    kotlin.text.n nVar = Regex.b;
                                    String strSubstring2 = str5.substring(i22);
                                    Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                                    nVar.getClass();
                                    sb.append(kotlin.text.n.a(strSubstring2));
                                }
                                sb.append("$");
                                String string = sb.toString();
                                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                                c1300w.a = C1301x.i(string);
                                linkedHashMap.put(str4, c1300w);
                            }
                        }
                        return linkedHashMap;
                    case 3:
                        String uriString2 = this.b.a;
                        if (uriString2 != null) {
                            Intrinsics.checkNotNullParameter(uriString2, "uriString");
                            Uri uri2 = Uri.parse(uriString2);
                            Intrinsics.checkNotNullExpressionValue(uri2, "parse(...)");
                            if (uri2.getFragment() != null) {
                                ArrayList arrayList2 = new ArrayList();
                                Intrinsics.checkNotNullParameter(uriString2, "uriString");
                                Uri uri3 = Uri.parse(uriString2);
                                Intrinsics.checkNotNullExpressionValue(uri3, "parse(...)");
                                String fragment = uri3.getFragment();
                                StringBuilder sb2 = new StringBuilder();
                                Intrinsics.d(fragment);
                                C1301x.a(fragment, sb2, arrayList2);
                                return new Pair(arrayList2, sb2.toString());
                            }
                        }
                        return null;
                    case 4:
                        Pair pair = (Pair) this.b.h.getValue();
                        return (pair == null || (list = (List) pair.a) == null) ? new ArrayList() : list;
                    case 5:
                        Pair pair2 = (Pair) this.b.h.getValue();
                        if (pair2 != null) {
                            return (String) pair2.b;
                        }
                        return null;
                    case 6:
                        String str6 = (String) this.b.j.getValue();
                        if (str6 != null) {
                            return new Regex(str6, kotlin.text.s.b);
                        }
                        return null;
                    default:
                        this.b.getClass();
                        return null;
                }
            }
        });
        final int i4 = 3;
        this.h = kotlin.l.a(mVar, new Function0(this) { // from class: androidx.navigation.u
            public final /* synthetic */ C1301x b;

            {
                this.b = this;
            }

            /* JADX WARN: Type inference failed for: r0v20, types: [java.lang.Object, kotlin.k] */
            /* JADX WARN: Type inference failed for: r0v27, types: [java.lang.Object, kotlin.k] */
            /* JADX WARN: Type inference failed for: r0v34, types: [java.lang.Object, kotlin.k] */
            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                List list;
                switch (i4) {
                    case 0:
                        String str2 = this.b.c;
                        if (str2 != null) {
                            return new Regex(str2, kotlin.text.s.b);
                        }
                        return null;
                    case 1:
                        String str3 = this.b.a;
                        return Boolean.valueOf(str3 != null && C1301x.r.e(str3));
                    case 2:
                        C1301x c1301x = this.b;
                        c1301x.getClass();
                        LinkedHashMap linkedHashMap = new LinkedHashMap();
                        if (((Boolean) c1301x.e.getValue()).booleanValue()) {
                            String uriString = c1301x.a;
                            Intrinsics.d(uriString);
                            Intrinsics.checkNotNullParameter(uriString, "uriString");
                            Uri uri = Uri.parse(uriString);
                            Intrinsics.checkNotNullExpressionValue(uri, "parse(...)");
                            for (String str4 : uri.getQueryParameterNames()) {
                                StringBuilder sb = new StringBuilder();
                                List<String> queryParameters = uri.getQueryParameters(str4);
                                if (queryParameters.size() > 1) {
                                    throw new IllegalArgumentException(AbstractC0147y.e("Query parameter ", str4, " must only be present once in ", uriString, ". To support repeated query parameters, use an array type for your argument and the pattern provided in your URI will be used to parse each query parameter instance.").toString());
                                }
                                String str5 = (String) CollectionsKt.firstOrNull(queryParameters);
                                if (str5 == null) {
                                    c1301x.g = true;
                                    str5 = str4;
                                }
                                C1300w c1300w = new C1300w();
                                int i22 = 0;
                                for (kotlin.text.m mVarB = C1301x.n.b(str5); mVarB != null; mVarB = mVarB.next()) {
                                    MatchGroup matchGroupB = mVarB.c.b(1);
                                    Intrinsics.d(matchGroupB);
                                    String name = matchGroupB.a;
                                    Intrinsics.checkNotNullParameter(name, "name");
                                    c1300w.b.add(name);
                                    if (mVarB.c().a > i22) {
                                        String strSubstring = str5.substring(i22, mVarB.c().a);
                                        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                                        Regex.b.getClass();
                                        sb.append(kotlin.text.n.a(strSubstring));
                                    }
                                    sb.append("([\\s\\S]+?)?");
                                    i22 = mVarB.c().b + 1;
                                }
                                if (i22 < str5.length()) {
                                    kotlin.text.n nVar = Regex.b;
                                    String strSubstring2 = str5.substring(i22);
                                    Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                                    nVar.getClass();
                                    sb.append(kotlin.text.n.a(strSubstring2));
                                }
                                sb.append("$");
                                String string = sb.toString();
                                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                                c1300w.a = C1301x.i(string);
                                linkedHashMap.put(str4, c1300w);
                            }
                        }
                        return linkedHashMap;
                    case 3:
                        String uriString2 = this.b.a;
                        if (uriString2 != null) {
                            Intrinsics.checkNotNullParameter(uriString2, "uriString");
                            Uri uri2 = Uri.parse(uriString2);
                            Intrinsics.checkNotNullExpressionValue(uri2, "parse(...)");
                            if (uri2.getFragment() != null) {
                                ArrayList arrayList2 = new ArrayList();
                                Intrinsics.checkNotNullParameter(uriString2, "uriString");
                                Uri uri3 = Uri.parse(uriString2);
                                Intrinsics.checkNotNullExpressionValue(uri3, "parse(...)");
                                String fragment = uri3.getFragment();
                                StringBuilder sb2 = new StringBuilder();
                                Intrinsics.d(fragment);
                                C1301x.a(fragment, sb2, arrayList2);
                                return new Pair(arrayList2, sb2.toString());
                            }
                        }
                        return null;
                    case 4:
                        Pair pair = (Pair) this.b.h.getValue();
                        return (pair == null || (list = (List) pair.a) == null) ? new ArrayList() : list;
                    case 5:
                        Pair pair2 = (Pair) this.b.h.getValue();
                        if (pair2 != null) {
                            return (String) pair2.b;
                        }
                        return null;
                    case 6:
                        String str6 = (String) this.b.j.getValue();
                        if (str6 != null) {
                            return new Regex(str6, kotlin.text.s.b);
                        }
                        return null;
                    default:
                        this.b.getClass();
                        return null;
                }
            }
        });
        final int i5 = 4;
        this.i = kotlin.l.a(mVar, new Function0(this) { // from class: androidx.navigation.u
            public final /* synthetic */ C1301x b;

            {
                this.b = this;
            }

            /* JADX WARN: Type inference failed for: r0v20, types: [java.lang.Object, kotlin.k] */
            /* JADX WARN: Type inference failed for: r0v27, types: [java.lang.Object, kotlin.k] */
            /* JADX WARN: Type inference failed for: r0v34, types: [java.lang.Object, kotlin.k] */
            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                List list;
                switch (i5) {
                    case 0:
                        String str2 = this.b.c;
                        if (str2 != null) {
                            return new Regex(str2, kotlin.text.s.b);
                        }
                        return null;
                    case 1:
                        String str3 = this.b.a;
                        return Boolean.valueOf(str3 != null && C1301x.r.e(str3));
                    case 2:
                        C1301x c1301x = this.b;
                        c1301x.getClass();
                        LinkedHashMap linkedHashMap = new LinkedHashMap();
                        if (((Boolean) c1301x.e.getValue()).booleanValue()) {
                            String uriString = c1301x.a;
                            Intrinsics.d(uriString);
                            Intrinsics.checkNotNullParameter(uriString, "uriString");
                            Uri uri = Uri.parse(uriString);
                            Intrinsics.checkNotNullExpressionValue(uri, "parse(...)");
                            for (String str4 : uri.getQueryParameterNames()) {
                                StringBuilder sb = new StringBuilder();
                                List<String> queryParameters = uri.getQueryParameters(str4);
                                if (queryParameters.size() > 1) {
                                    throw new IllegalArgumentException(AbstractC0147y.e("Query parameter ", str4, " must only be present once in ", uriString, ". To support repeated query parameters, use an array type for your argument and the pattern provided in your URI will be used to parse each query parameter instance.").toString());
                                }
                                String str5 = (String) CollectionsKt.firstOrNull(queryParameters);
                                if (str5 == null) {
                                    c1301x.g = true;
                                    str5 = str4;
                                }
                                C1300w c1300w = new C1300w();
                                int i22 = 0;
                                for (kotlin.text.m mVarB = C1301x.n.b(str5); mVarB != null; mVarB = mVarB.next()) {
                                    MatchGroup matchGroupB = mVarB.c.b(1);
                                    Intrinsics.d(matchGroupB);
                                    String name = matchGroupB.a;
                                    Intrinsics.checkNotNullParameter(name, "name");
                                    c1300w.b.add(name);
                                    if (mVarB.c().a > i22) {
                                        String strSubstring = str5.substring(i22, mVarB.c().a);
                                        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                                        Regex.b.getClass();
                                        sb.append(kotlin.text.n.a(strSubstring));
                                    }
                                    sb.append("([\\s\\S]+?)?");
                                    i22 = mVarB.c().b + 1;
                                }
                                if (i22 < str5.length()) {
                                    kotlin.text.n nVar = Regex.b;
                                    String strSubstring2 = str5.substring(i22);
                                    Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                                    nVar.getClass();
                                    sb.append(kotlin.text.n.a(strSubstring2));
                                }
                                sb.append("$");
                                String string = sb.toString();
                                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                                c1300w.a = C1301x.i(string);
                                linkedHashMap.put(str4, c1300w);
                            }
                        }
                        return linkedHashMap;
                    case 3:
                        String uriString2 = this.b.a;
                        if (uriString2 != null) {
                            Intrinsics.checkNotNullParameter(uriString2, "uriString");
                            Uri uri2 = Uri.parse(uriString2);
                            Intrinsics.checkNotNullExpressionValue(uri2, "parse(...)");
                            if (uri2.getFragment() != null) {
                                ArrayList arrayList2 = new ArrayList();
                                Intrinsics.checkNotNullParameter(uriString2, "uriString");
                                Uri uri3 = Uri.parse(uriString2);
                                Intrinsics.checkNotNullExpressionValue(uri3, "parse(...)");
                                String fragment = uri3.getFragment();
                                StringBuilder sb2 = new StringBuilder();
                                Intrinsics.d(fragment);
                                C1301x.a(fragment, sb2, arrayList2);
                                return new Pair(arrayList2, sb2.toString());
                            }
                        }
                        return null;
                    case 4:
                        Pair pair = (Pair) this.b.h.getValue();
                        return (pair == null || (list = (List) pair.a) == null) ? new ArrayList() : list;
                    case 5:
                        Pair pair2 = (Pair) this.b.h.getValue();
                        if (pair2 != null) {
                            return (String) pair2.b;
                        }
                        return null;
                    case 6:
                        String str6 = (String) this.b.j.getValue();
                        if (str6 != null) {
                            return new Regex(str6, kotlin.text.s.b);
                        }
                        return null;
                    default:
                        this.b.getClass();
                        return null;
                }
            }
        });
        final int i6 = 5;
        this.j = kotlin.l.a(mVar, new Function0(this) { // from class: androidx.navigation.u
            public final /* synthetic */ C1301x b;

            {
                this.b = this;
            }

            /* JADX WARN: Type inference failed for: r0v20, types: [java.lang.Object, kotlin.k] */
            /* JADX WARN: Type inference failed for: r0v27, types: [java.lang.Object, kotlin.k] */
            /* JADX WARN: Type inference failed for: r0v34, types: [java.lang.Object, kotlin.k] */
            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                List list;
                switch (i6) {
                    case 0:
                        String str2 = this.b.c;
                        if (str2 != null) {
                            return new Regex(str2, kotlin.text.s.b);
                        }
                        return null;
                    case 1:
                        String str3 = this.b.a;
                        return Boolean.valueOf(str3 != null && C1301x.r.e(str3));
                    case 2:
                        C1301x c1301x = this.b;
                        c1301x.getClass();
                        LinkedHashMap linkedHashMap = new LinkedHashMap();
                        if (((Boolean) c1301x.e.getValue()).booleanValue()) {
                            String uriString = c1301x.a;
                            Intrinsics.d(uriString);
                            Intrinsics.checkNotNullParameter(uriString, "uriString");
                            Uri uri = Uri.parse(uriString);
                            Intrinsics.checkNotNullExpressionValue(uri, "parse(...)");
                            for (String str4 : uri.getQueryParameterNames()) {
                                StringBuilder sb = new StringBuilder();
                                List<String> queryParameters = uri.getQueryParameters(str4);
                                if (queryParameters.size() > 1) {
                                    throw new IllegalArgumentException(AbstractC0147y.e("Query parameter ", str4, " must only be present once in ", uriString, ". To support repeated query parameters, use an array type for your argument and the pattern provided in your URI will be used to parse each query parameter instance.").toString());
                                }
                                String str5 = (String) CollectionsKt.firstOrNull(queryParameters);
                                if (str5 == null) {
                                    c1301x.g = true;
                                    str5 = str4;
                                }
                                C1300w c1300w = new C1300w();
                                int i22 = 0;
                                for (kotlin.text.m mVarB = C1301x.n.b(str5); mVarB != null; mVarB = mVarB.next()) {
                                    MatchGroup matchGroupB = mVarB.c.b(1);
                                    Intrinsics.d(matchGroupB);
                                    String name = matchGroupB.a;
                                    Intrinsics.checkNotNullParameter(name, "name");
                                    c1300w.b.add(name);
                                    if (mVarB.c().a > i22) {
                                        String strSubstring = str5.substring(i22, mVarB.c().a);
                                        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                                        Regex.b.getClass();
                                        sb.append(kotlin.text.n.a(strSubstring));
                                    }
                                    sb.append("([\\s\\S]+?)?");
                                    i22 = mVarB.c().b + 1;
                                }
                                if (i22 < str5.length()) {
                                    kotlin.text.n nVar = Regex.b;
                                    String strSubstring2 = str5.substring(i22);
                                    Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                                    nVar.getClass();
                                    sb.append(kotlin.text.n.a(strSubstring2));
                                }
                                sb.append("$");
                                String string = sb.toString();
                                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                                c1300w.a = C1301x.i(string);
                                linkedHashMap.put(str4, c1300w);
                            }
                        }
                        return linkedHashMap;
                    case 3:
                        String uriString2 = this.b.a;
                        if (uriString2 != null) {
                            Intrinsics.checkNotNullParameter(uriString2, "uriString");
                            Uri uri2 = Uri.parse(uriString2);
                            Intrinsics.checkNotNullExpressionValue(uri2, "parse(...)");
                            if (uri2.getFragment() != null) {
                                ArrayList arrayList2 = new ArrayList();
                                Intrinsics.checkNotNullParameter(uriString2, "uriString");
                                Uri uri3 = Uri.parse(uriString2);
                                Intrinsics.checkNotNullExpressionValue(uri3, "parse(...)");
                                String fragment = uri3.getFragment();
                                StringBuilder sb2 = new StringBuilder();
                                Intrinsics.d(fragment);
                                C1301x.a(fragment, sb2, arrayList2);
                                return new Pair(arrayList2, sb2.toString());
                            }
                        }
                        return null;
                    case 4:
                        Pair pair = (Pair) this.b.h.getValue();
                        return (pair == null || (list = (List) pair.a) == null) ? new ArrayList() : list;
                    case 5:
                        Pair pair2 = (Pair) this.b.h.getValue();
                        if (pair2 != null) {
                            return (String) pair2.b;
                        }
                        return null;
                    case 6:
                        String str6 = (String) this.b.j.getValue();
                        if (str6 != null) {
                            return new Regex(str6, kotlin.text.s.b);
                        }
                        return null;
                    default:
                        this.b.getClass();
                        return null;
                }
            }
        });
        final int i7 = 6;
        this.k = kotlin.l.b(new Function0(this) { // from class: androidx.navigation.u
            public final /* synthetic */ C1301x b;

            {
                this.b = this;
            }

            /* JADX WARN: Type inference failed for: r0v20, types: [java.lang.Object, kotlin.k] */
            /* JADX WARN: Type inference failed for: r0v27, types: [java.lang.Object, kotlin.k] */
            /* JADX WARN: Type inference failed for: r0v34, types: [java.lang.Object, kotlin.k] */
            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                List list;
                switch (i7) {
                    case 0:
                        String str2 = this.b.c;
                        if (str2 != null) {
                            return new Regex(str2, kotlin.text.s.b);
                        }
                        return null;
                    case 1:
                        String str3 = this.b.a;
                        return Boolean.valueOf(str3 != null && C1301x.r.e(str3));
                    case 2:
                        C1301x c1301x = this.b;
                        c1301x.getClass();
                        LinkedHashMap linkedHashMap = new LinkedHashMap();
                        if (((Boolean) c1301x.e.getValue()).booleanValue()) {
                            String uriString = c1301x.a;
                            Intrinsics.d(uriString);
                            Intrinsics.checkNotNullParameter(uriString, "uriString");
                            Uri uri = Uri.parse(uriString);
                            Intrinsics.checkNotNullExpressionValue(uri, "parse(...)");
                            for (String str4 : uri.getQueryParameterNames()) {
                                StringBuilder sb = new StringBuilder();
                                List<String> queryParameters = uri.getQueryParameters(str4);
                                if (queryParameters.size() > 1) {
                                    throw new IllegalArgumentException(AbstractC0147y.e("Query parameter ", str4, " must only be present once in ", uriString, ". To support repeated query parameters, use an array type for your argument and the pattern provided in your URI will be used to parse each query parameter instance.").toString());
                                }
                                String str5 = (String) CollectionsKt.firstOrNull(queryParameters);
                                if (str5 == null) {
                                    c1301x.g = true;
                                    str5 = str4;
                                }
                                C1300w c1300w = new C1300w();
                                int i22 = 0;
                                for (kotlin.text.m mVarB = C1301x.n.b(str5); mVarB != null; mVarB = mVarB.next()) {
                                    MatchGroup matchGroupB = mVarB.c.b(1);
                                    Intrinsics.d(matchGroupB);
                                    String name = matchGroupB.a;
                                    Intrinsics.checkNotNullParameter(name, "name");
                                    c1300w.b.add(name);
                                    if (mVarB.c().a > i22) {
                                        String strSubstring = str5.substring(i22, mVarB.c().a);
                                        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                                        Regex.b.getClass();
                                        sb.append(kotlin.text.n.a(strSubstring));
                                    }
                                    sb.append("([\\s\\S]+?)?");
                                    i22 = mVarB.c().b + 1;
                                }
                                if (i22 < str5.length()) {
                                    kotlin.text.n nVar = Regex.b;
                                    String strSubstring2 = str5.substring(i22);
                                    Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                                    nVar.getClass();
                                    sb.append(kotlin.text.n.a(strSubstring2));
                                }
                                sb.append("$");
                                String string = sb.toString();
                                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                                c1300w.a = C1301x.i(string);
                                linkedHashMap.put(str4, c1300w);
                            }
                        }
                        return linkedHashMap;
                    case 3:
                        String uriString2 = this.b.a;
                        if (uriString2 != null) {
                            Intrinsics.checkNotNullParameter(uriString2, "uriString");
                            Uri uri2 = Uri.parse(uriString2);
                            Intrinsics.checkNotNullExpressionValue(uri2, "parse(...)");
                            if (uri2.getFragment() != null) {
                                ArrayList arrayList2 = new ArrayList();
                                Intrinsics.checkNotNullParameter(uriString2, "uriString");
                                Uri uri3 = Uri.parse(uriString2);
                                Intrinsics.checkNotNullExpressionValue(uri3, "parse(...)");
                                String fragment = uri3.getFragment();
                                StringBuilder sb2 = new StringBuilder();
                                Intrinsics.d(fragment);
                                C1301x.a(fragment, sb2, arrayList2);
                                return new Pair(arrayList2, sb2.toString());
                            }
                        }
                        return null;
                    case 4:
                        Pair pair = (Pair) this.b.h.getValue();
                        return (pair == null || (list = (List) pair.a) == null) ? new ArrayList() : list;
                    case 5:
                        Pair pair2 = (Pair) this.b.h.getValue();
                        if (pair2 != null) {
                            return (String) pair2.b;
                        }
                        return null;
                    case 6:
                        String str6 = (String) this.b.j.getValue();
                        if (str6 != null) {
                            return new Regex(str6, kotlin.text.s.b);
                        }
                        return null;
                    default:
                        this.b.getClass();
                        return null;
                }
            }
        });
        final int i8 = 7;
        kotlin.l.b(new Function0(this) { // from class: androidx.navigation.u
            public final /* synthetic */ C1301x b;

            {
                this.b = this;
            }

            /* JADX WARN: Type inference failed for: r0v20, types: [java.lang.Object, kotlin.k] */
            /* JADX WARN: Type inference failed for: r0v27, types: [java.lang.Object, kotlin.k] */
            /* JADX WARN: Type inference failed for: r0v34, types: [java.lang.Object, kotlin.k] */
            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                List list;
                switch (i8) {
                    case 0:
                        String str2 = this.b.c;
                        if (str2 != null) {
                            return new Regex(str2, kotlin.text.s.b);
                        }
                        return null;
                    case 1:
                        String str3 = this.b.a;
                        return Boolean.valueOf(str3 != null && C1301x.r.e(str3));
                    case 2:
                        C1301x c1301x = this.b;
                        c1301x.getClass();
                        LinkedHashMap linkedHashMap = new LinkedHashMap();
                        if (((Boolean) c1301x.e.getValue()).booleanValue()) {
                            String uriString = c1301x.a;
                            Intrinsics.d(uriString);
                            Intrinsics.checkNotNullParameter(uriString, "uriString");
                            Uri uri = Uri.parse(uriString);
                            Intrinsics.checkNotNullExpressionValue(uri, "parse(...)");
                            for (String str4 : uri.getQueryParameterNames()) {
                                StringBuilder sb = new StringBuilder();
                                List<String> queryParameters = uri.getQueryParameters(str4);
                                if (queryParameters.size() > 1) {
                                    throw new IllegalArgumentException(AbstractC0147y.e("Query parameter ", str4, " must only be present once in ", uriString, ". To support repeated query parameters, use an array type for your argument and the pattern provided in your URI will be used to parse each query parameter instance.").toString());
                                }
                                String str5 = (String) CollectionsKt.firstOrNull(queryParameters);
                                if (str5 == null) {
                                    c1301x.g = true;
                                    str5 = str4;
                                }
                                C1300w c1300w = new C1300w();
                                int i22 = 0;
                                for (kotlin.text.m mVarB = C1301x.n.b(str5); mVarB != null; mVarB = mVarB.next()) {
                                    MatchGroup matchGroupB = mVarB.c.b(1);
                                    Intrinsics.d(matchGroupB);
                                    String name = matchGroupB.a;
                                    Intrinsics.checkNotNullParameter(name, "name");
                                    c1300w.b.add(name);
                                    if (mVarB.c().a > i22) {
                                        String strSubstring = str5.substring(i22, mVarB.c().a);
                                        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                                        Regex.b.getClass();
                                        sb.append(kotlin.text.n.a(strSubstring));
                                    }
                                    sb.append("([\\s\\S]+?)?");
                                    i22 = mVarB.c().b + 1;
                                }
                                if (i22 < str5.length()) {
                                    kotlin.text.n nVar = Regex.b;
                                    String strSubstring2 = str5.substring(i22);
                                    Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                                    nVar.getClass();
                                    sb.append(kotlin.text.n.a(strSubstring2));
                                }
                                sb.append("$");
                                String string = sb.toString();
                                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                                c1300w.a = C1301x.i(string);
                                linkedHashMap.put(str4, c1300w);
                            }
                        }
                        return linkedHashMap;
                    case 3:
                        String uriString2 = this.b.a;
                        if (uriString2 != null) {
                            Intrinsics.checkNotNullParameter(uriString2, "uriString");
                            Uri uri2 = Uri.parse(uriString2);
                            Intrinsics.checkNotNullExpressionValue(uri2, "parse(...)");
                            if (uri2.getFragment() != null) {
                                ArrayList arrayList2 = new ArrayList();
                                Intrinsics.checkNotNullParameter(uriString2, "uriString");
                                Uri uri3 = Uri.parse(uriString2);
                                Intrinsics.checkNotNullExpressionValue(uri3, "parse(...)");
                                String fragment = uri3.getFragment();
                                StringBuilder sb2 = new StringBuilder();
                                Intrinsics.d(fragment);
                                C1301x.a(fragment, sb2, arrayList2);
                                return new Pair(arrayList2, sb2.toString());
                            }
                        }
                        return null;
                    case 4:
                        Pair pair = (Pair) this.b.h.getValue();
                        return (pair == null || (list = (List) pair.a) == null) ? new ArrayList() : list;
                    case 5:
                        Pair pair2 = (Pair) this.b.h.getValue();
                        if (pair2 != null) {
                            return (String) pair2.b;
                        }
                        return null;
                    case 6:
                        String str6 = (String) this.b.j.getValue();
                        if (str6 != null) {
                            return new Regex(str6, kotlin.text.s.b);
                        }
                        return null;
                    default:
                        this.b.getClass();
                        return null;
                }
            }
        });
        if (str == null) {
            return;
        }
        StringBuilder sb = new StringBuilder("^");
        if (!m.a(str)) {
            String strPattern = o.a.pattern();
            Intrinsics.checkNotNullExpressionValue(strPattern, "pattern(...)");
            sb.append(strPattern);
        }
        kotlin.text.m mVarB = new Regex("(\\?|#|$)").b(str);
        if (mVarB != null) {
            boolean z = false;
            String strSubstring = str.substring(0, mVarB.c().a);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
            a(strSubstring, sb, arrayList);
            if (!p.a(sb) && !q.a(sb)) {
                z = true;
            }
            this.l = z;
            sb.append("($|(\\?(.)*)|(#(.)*))");
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        this.c = i(string);
    }

    public static void a(String str, StringBuilder sb, ArrayList arrayList) {
        int i = 0;
        for (kotlin.text.m mVarB = n.b(str); mVarB != null; mVarB = mVarB.next()) {
            MatchGroup matchGroupB = mVarB.c.b(1);
            Intrinsics.d(matchGroupB);
            arrayList.add(matchGroupB.a);
            if (mVarB.c().a > i) {
                kotlin.text.n nVar = Regex.b;
                String strSubstring = str.substring(i, mVarB.c().a);
                Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                nVar.getClass();
                sb.append(kotlin.text.n.a(strSubstring));
            }
            String strPattern = q.a.pattern();
            Intrinsics.checkNotNullExpressionValue(strPattern, "pattern(...)");
            sb.append(strPattern);
            i = mVarB.c().b + 1;
        }
        if (i < str.length()) {
            kotlin.text.n nVar2 = Regex.b;
            String strSubstring2 = str.substring(i);
            Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
            nVar2.getClass();
            sb.append(kotlin.text.n.a(strSubstring2));
        }
    }

    public static void g(Bundle source, String key, String value, C1289k c1289k) {
        if (c1289k == null) {
            Intrinsics.checkNotNullParameter(source, "source");
            AbstractC3343g2.h(key, value, source);
            return;
        }
        S s = c1289k.a;
        Intrinsics.checkNotNullParameter(source, "bundle");
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(s, "<this>");
        Intrinsics.checkNotNullParameter(source, "bundle");
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        s.e(source, key, s.d(value));
    }

    public static boolean h(Bundle source, String key, String str, C1289k c1289k) {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(key, "key");
        if (!source.containsKey(key)) {
            return true;
        }
        if (c1289k == null) {
            return false;
        }
        S s = c1289k.a;
        Object objA = s.a(source, key);
        Intrinsics.checkNotNullParameter(source, "bundle");
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(s, "<this>");
        Intrinsics.checkNotNullParameter(source, "bundle");
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(key, "key");
        if (!source.containsKey(key)) {
            throw new IllegalArgumentException("There is no previous value in this savedState.");
        }
        s.e(source, key, s.c(objA, str));
        return false;
    }

    public static String i(String str) {
        return (StringsKt.G(str, "\\Q", false) && StringsKt.G(str, "\\E", false)) ? kotlin.text.D.o(str, ".*", "\\E.*\\Q", false) : StringsKt.G(str, "\\.\\*", false) ? kotlin.text.D.o(str, "\\.\\*", ".*", false) : str;
    }

    public final int b(Uri uri) {
        String uriString;
        if (uri == null || (uriString = this.a) == null) {
            return 0;
        }
        List<String> pathSegments = uri.getPathSegments();
        Intrinsics.checkNotNullParameter(uriString, "uriString");
        Uri uri2 = Uri.parse(uriString);
        Intrinsics.checkNotNullExpressionValue(uri2, "parse(...)");
        return CollectionsKt.Q(pathSegments, uri2.getPathSegments()).size();
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r1v6, types: [java.lang.Object, kotlin.k] */
    public final ArrayList c() {
        ArrayList arrayList = this.b;
        Collection collectionValues = ((Map) this.f.getValue()).values();
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = collectionValues.iterator();
        while (it2.hasNext()) {
            kotlin.collections.G.u(arrayList2, ((C1300w) it2.next()).b);
        }
        return CollectionsKt.c0(CollectionsKt.c0(arrayList, arrayList2), (List) this.i.getValue());
    }

    /* JADX WARN: Type inference failed for: r0v15, types: [java.lang.Object, kotlin.k] */
    public final Bundle d(Uri deepLink, LinkedHashMap arguments) {
        kotlin.text.m mVarD;
        kotlin.text.m mVarD2;
        String strDecode;
        String s;
        Intrinsics.checkNotNullParameter(deepLink, "deepLink");
        Intrinsics.checkNotNullParameter(arguments, "arguments");
        Regex regex = (Regex) this.d.getValue();
        if (regex != null && (mVarD = regex.d(deepLink.toString())) != null) {
            kotlin.collections.V.c();
            int i = 0;
            Bundle source = AbstractC3206m6.a((Pair[]) Arrays.copyOf(new Pair[0], 0));
            Intrinsics.checkNotNullParameter(source, "source");
            if (e(mVarD, source, arguments) && (!((Boolean) this.e.getValue()).booleanValue() || f(deepLink, source, arguments))) {
                String fragment = deepLink.getFragment();
                Regex regex2 = (Regex) this.k.getValue();
                if (regex2 != null && (mVarD2 = regex2.d(String.valueOf(fragment))) != null) {
                    List list = (List) this.i.getValue();
                    ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
                    for (Object obj : list) {
                        int i2 = i + 1;
                        if (i < 0) {
                            kotlin.collections.B.p();
                            throw null;
                        }
                        String str = (String) obj;
                        MatchGroup matchGroupB = mVarD2.c.b(i2);
                        if (matchGroupB == null || (s = matchGroupB.a) == null) {
                            strDecode = null;
                        } else {
                            Intrinsics.checkNotNullParameter(s, "s");
                            strDecode = Uri.decode(s);
                            Intrinsics.checkNotNullExpressionValue(strDecode, "decode(...)");
                        }
                        if (strDecode == null) {
                            strDecode = "";
                        }
                        try {
                            g(source, str, strDecode, (C1289k) arguments.get(str));
                            arrayList.add(Unit.a);
                            i = i2;
                        } catch (IllegalArgumentException unused) {
                        }
                    }
                }
                if (E1.b(arguments, new C1299v(source, 0)).isEmpty()) {
                    return source;
                }
            }
        }
        return null;
    }

    public final boolean e(kotlin.text.m mVar, Bundle bundle, LinkedHashMap linkedHashMap) {
        String s;
        ArrayList arrayList = this.b;
        ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        int i = 0;
        while (it2.hasNext()) {
            Object next = it2.next();
            int i2 = i + 1;
            String strDecode = null;
            if (i < 0) {
                kotlin.collections.B.p();
                throw null;
            }
            String str = (String) next;
            MatchGroup matchGroupB = mVar.c.b(i2);
            if (matchGroupB != null && (s = matchGroupB.a) != null) {
                Intrinsics.checkNotNullParameter(s, "s");
                strDecode = Uri.decode(s);
                Intrinsics.checkNotNullExpressionValue(strDecode, "decode(...)");
            }
            if (strDecode == null) {
                strDecode = "";
            }
            try {
                g(bundle, str, strDecode, (C1289k) linkedHashMap.get(str));
                arrayList2.add(Unit.a);
                i = i2;
            } catch (IllegalArgumentException unused) {
                return false;
            }
        }
        return true;
    }

    public final boolean equals(Object obj) {
        if (obj == null || !(obj instanceof C1301x)) {
            return false;
        }
        return Intrinsics.b(this.a, ((C1301x) obj).a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r14v2 */
    /* JADX WARN: Type inference failed for: r14v3, types: [int] */
    /* JADX WARN: Type inference failed for: r14v9 */
    /* JADX WARN: Type inference failed for: r21v0, types: [java.util.LinkedHashMap] */
    /* JADX WARN: Type inference failed for: r3v0, types: [java.lang.Object, kotlin.k] */
    public final boolean f(Uri uri, Bundle source, LinkedHashMap linkedHashMap) {
        Object objValueOf;
        String query;
        for (Map.Entry entry : ((Map) this.f.getValue()).entrySet()) {
            String str = (String) entry.getKey();
            C1300w c1300w = (C1300w) entry.getValue();
            List<String> queryParameters = uri.getQueryParameters(str);
            if (this.g && (query = uri.getQuery()) != null && !query.equals(uri.toString())) {
                queryParameters = kotlin.collections.A.b(query);
            }
            kotlin.collections.V.c();
            boolean z = false;
            Bundle from = AbstractC3206m6.a((Pair[]) Arrays.copyOf(new Pair[0], 0));
            Intrinsics.checkNotNullParameter(from, "source");
            Iterator it2 = c1300w.b.iterator();
            while (it2.hasNext()) {
                String str2 = (String) it2.next();
                C1289k c1289k = (C1289k) linkedHashMap.get(str2);
                S s = c1289k != null ? c1289k.a : null;
                if ((s instanceof AbstractC1285g) && !c1289k.c) {
                    AbstractC1285g abstractC1285g = (AbstractC1285g) s;
                    abstractC1285g.e(from, str2, abstractC1285g.h());
                }
            }
            for (String str3 : queryParameters) {
                String str4 = c1300w.a;
                kotlin.text.m mVarD = str4 != null ? new Regex(str4).d(str3) : null;
                if (mVarD == null) {
                    return z;
                }
                ArrayList arrayList = c1300w.b;
                ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
                Iterator it3 = arrayList.iterator();
                ?? r14 = z;
                while (it3.hasNext()) {
                    Object next = it3.next();
                    int i = r14 + 1;
                    if (r14 < 0) {
                        kotlin.collections.B.p();
                        throw null;
                    }
                    String str5 = (String) next;
                    MatchGroup matchGroupB = mVarD.c.b(i);
                    String str6 = matchGroupB != null ? matchGroupB.a : null;
                    if (str6 == null) {
                        str6 = "";
                    }
                    C1289k c1289k2 = (C1289k) linkedHashMap.get(str5);
                    try {
                        Intrinsics.checkNotNullParameter(from, "source");
                        if (AbstractC3335e2.a(from, str5)) {
                            objValueOf = Boolean.valueOf(h(from, str5, str6, c1289k2));
                        } else {
                            g(from, str5, str6, c1289k2);
                            objValueOf = Unit.a;
                        }
                    } catch (IllegalArgumentException unused) {
                        objValueOf = Unit.a;
                    }
                    arrayList2.add(objValueOf);
                    r14 = i;
                    z = false;
                }
            }
            Intrinsics.checkNotNullParameter(source, "source");
            Intrinsics.checkNotNullParameter(from, "from");
            source.putAll(from);
        }
        return true;
    }

    public final int hashCode() {
        String str = this.a;
        return (str != null ? str.hashCode() : 0) * 961;
    }
}
