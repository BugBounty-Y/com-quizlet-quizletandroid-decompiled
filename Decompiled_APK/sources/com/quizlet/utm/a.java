package com.quizlet.utm;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.collections.U;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.CharsKt;
import kotlin.text.Regex;
import kotlin.text.StringsKt;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class a {

    @NotNull
    private static final Map<com.quizlet.utm.campaigns.b, Character> CAMPAIGN_MAP;

    @NotNull
    private static final String CHARS_MAP = "0qjKtxWUYS1AlN6Ibrmf7HsF3o2kOzLeEhC5aDQZRd9MPwyGTBngipv4cVJu8X-._~!";
    private static final int CURRENT_VERSION = 1;
    private static final int DECODED_CHARS_LENGTH = 4;

    @NotNull
    public static final a INSTANCE = new a();

    @NotNull
    private static final Map<com.quizlet.utm.mediums.b, Character> MEDIUM_MAP;

    @NotNull
    private static final Map<com.quizlet.utm.sources.b, Character> SOURCE_MAP;
    private static final char USER_ID_GET_PARAM = 'i';
    private static final char UTM_GET_PARAM = 'x';

    /* renamed from: com.quizlet.utm.a$a, reason: collision with other inner class name */
    public static final class C0023a {
        private final c params;
        private final Long userId;

        /* JADX WARN: Multi-variable type inference failed */
        public C0023a() {
            this(null, 0 == true ? 1 : 0, 3, 0 == true ? 1 : 0);
        }

        public static /* synthetic */ C0023a copy$default(C0023a c0023a, c cVar, Long l, int i, Object obj) {
            if ((i & 1) != 0) {
                cVar = c0023a.params;
            }
            if ((i & 2) != 0) {
                l = c0023a.userId;
            }
            return c0023a.copy(cVar, l);
        }

        public final c component1() {
            return this.params;
        }

        public final Long component2() {
            return this.userId;
        }

        @NotNull
        public final C0023a copy(c cVar, Long l) {
            return new C0023a(cVar, l);
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof C0023a)) {
                return false;
            }
            C0023a c0023a = (C0023a) obj;
            return Intrinsics.b(this.params, c0023a.params) && Intrinsics.b(this.userId, c0023a.userId);
        }

        public final c getParams() {
            return this.params;
        }

        public final Long getUserId() {
            return this.userId;
        }

        public int hashCode() {
            c cVar = this.params;
            int iHashCode = (cVar == null ? 0 : cVar.hashCode()) * 31;
            Long l = this.userId;
            return iHashCode + (l != null ? l.hashCode() : 0);
        }

        @NotNull
        public String toString() {
            return "DecodedUriParams(params=" + this.params + ", userId=" + this.userId + ")";
        }

        public C0023a(c cVar, Long l) {
            this.params = cVar;
            this.userId = l;
        }

        public /* synthetic */ C0023a(c cVar, Long l, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : cVar, (i & 2) != 0 ? null : l);
        }
    }

    public static final class b {
        private final String userId;

        @NotNull
        private final String utmBlob;

        public b(String str, @NotNull String utmBlob) {
            Intrinsics.checkNotNullParameter(utmBlob, "utmBlob");
            this.userId = str;
            this.utmBlob = utmBlob;
        }

        public static /* synthetic */ b copy$default(b bVar, String str, String str2, int i, Object obj) {
            if ((i & 1) != 0) {
                str = bVar.userId;
            }
            if ((i & 2) != 0) {
                str2 = bVar.utmBlob;
            }
            return bVar.copy(str, str2);
        }

        public final String component1() {
            return this.userId;
        }

        @NotNull
        public final String component2() {
            return this.utmBlob;
        }

        @NotNull
        public final b copy(String str, @NotNull String utmBlob) {
            Intrinsics.checkNotNullParameter(utmBlob, "utmBlob");
            return new b(str, utmBlob);
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof b)) {
                return false;
            }
            b bVar = (b) obj;
            return Intrinsics.b(this.userId, bVar.userId) && Intrinsics.b(this.utmBlob, bVar.utmBlob);
        }

        public final String getUserId() {
            return this.userId;
        }

        @NotNull
        public final String getUtmBlob() {
            return this.utmBlob;
        }

        public int hashCode() {
            String str = this.userId;
            return this.utmBlob.hashCode() + ((str == null ? 0 : str.hashCode()) * 31);
        }

        @NotNull
        public String toString() {
            return AbstractC0147y.e("EncodedUTMParams(userId=", this.userId, ", utmBlob=", this.utmBlob, ")");
        }
    }

    public static final class c {
        private final com.quizlet.utm.campaigns.b campaign;
        private final com.quizlet.utm.mediums.b medium;
        private final com.quizlet.utm.sources.b source;

        public c() {
            this(null, null, null, 7, null);
        }

        public static /* synthetic */ c copy$default(c cVar, com.quizlet.utm.campaigns.b bVar, com.quizlet.utm.mediums.b bVar2, com.quizlet.utm.sources.b bVar3, int i, Object obj) {
            if ((i & 1) != 0) {
                bVar = cVar.campaign;
            }
            if ((i & 2) != 0) {
                bVar2 = cVar.medium;
            }
            if ((i & 4) != 0) {
                bVar3 = cVar.source;
            }
            return cVar.copy(bVar, bVar2, bVar3);
        }

        public final com.quizlet.utm.campaigns.b component1() {
            return this.campaign;
        }

        public final com.quizlet.utm.mediums.b component2() {
            return this.medium;
        }

        public final com.quizlet.utm.sources.b component3() {
            return this.source;
        }

        @NotNull
        public final c copy(com.quizlet.utm.campaigns.b bVar, com.quizlet.utm.mediums.b bVar2, com.quizlet.utm.sources.b bVar3) {
            return new c(bVar, bVar2, bVar3);
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof c)) {
                return false;
            }
            c cVar = (c) obj;
            return this.campaign == cVar.campaign && this.medium == cVar.medium && this.source == cVar.source;
        }

        public final com.quizlet.utm.campaigns.b getCampaign() {
            return this.campaign;
        }

        public final com.quizlet.utm.mediums.b getMedium() {
            return this.medium;
        }

        public final com.quizlet.utm.sources.b getSource() {
            return this.source;
        }

        public int hashCode() {
            com.quizlet.utm.campaigns.b bVar = this.campaign;
            int iHashCode = (bVar == null ? 0 : bVar.hashCode()) * 31;
            com.quizlet.utm.mediums.b bVar2 = this.medium;
            int iHashCode2 = (iHashCode + (bVar2 == null ? 0 : bVar2.hashCode())) * 31;
            com.quizlet.utm.sources.b bVar3 = this.source;
            return iHashCode2 + (bVar3 != null ? bVar3.hashCode() : 0);
        }

        @NotNull
        public String toString() {
            return "UTMEnumParams(campaign=" + this.campaign + ", medium=" + this.medium + ", source=" + this.source + ")";
        }

        public c(com.quizlet.utm.campaigns.b bVar, com.quizlet.utm.mediums.b bVar2, com.quizlet.utm.sources.b bVar3) {
            this.campaign = bVar;
            this.medium = bVar2;
            this.source = bVar3;
        }

        public /* synthetic */ c(com.quizlet.utm.campaigns.b bVar, com.quizlet.utm.mediums.b bVar2, com.quizlet.utm.sources.b bVar3, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : bVar, (i & 2) != 0 ? null : bVar2, (i & 4) != 0 ? null : bVar3);
        }
    }

    static {
        com.quizlet.utm.campaigns.b[] bVarArrValues = com.quizlet.utm.campaigns.b.values();
        int iA = U.a(bVarArrValues.length);
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
        for (com.quizlet.utm.campaigns.b bVar : bVarArrValues) {
            linkedHashMap.put(bVar, Character.valueOf(CHARS_MAP.charAt(com.quizlet.utm.campaigns.a.valueOf(bVar.name()).getIndex())));
        }
        CAMPAIGN_MAP = linkedHashMap;
        com.quizlet.utm.mediums.b[] bVarArrValues2 = com.quizlet.utm.mediums.b.values();
        int iA2 = U.a(bVarArrValues2.length);
        if (iA2 < 16) {
            iA2 = 16;
        }
        LinkedHashMap linkedHashMap2 = new LinkedHashMap(iA2);
        for (com.quizlet.utm.mediums.b bVar2 : bVarArrValues2) {
            linkedHashMap2.put(bVar2, Character.valueOf(CHARS_MAP.charAt(com.quizlet.utm.mediums.a.valueOf(bVar2.name()).getIndex())));
        }
        MEDIUM_MAP = linkedHashMap2;
        com.quizlet.utm.sources.b[] bVarArrValues3 = com.quizlet.utm.sources.b.values();
        int iA3 = U.a(bVarArrValues3.length);
        LinkedHashMap linkedHashMap3 = new LinkedHashMap(iA3 >= 16 ? iA3 : 16);
        for (com.quizlet.utm.sources.b bVar3 : bVarArrValues3) {
            linkedHashMap3.put(bVar3, Character.valueOf(CHARS_MAP.charAt(com.quizlet.utm.sources.a.valueOf(bVar3.name()).getIndex())));
        }
        SOURCE_MAP = linkedHashMap3;
    }

    private a() {
    }

    @NotNull
    public static final c decodeUTM(String str) {
        if (str != null && str.length() == 4) {
            String strSubstring = str.substring(0, 1);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
            if (Integer.parseInt(strSubstring, CharsKt.checkRadix(10)) == 1) {
                a aVar = INSTANCE;
                return new c((com.quizlet.utm.campaigns.b) aVar.getDecodedValue(CAMPAIGN_MAP, Character.valueOf(str.charAt(1))), (com.quizlet.utm.mediums.b) aVar.getDecodedValue(MEDIUM_MAP, Character.valueOf(str.charAt(2))), (com.quizlet.utm.sources.b) aVar.getDecodedValue(SOURCE_MAP, Character.valueOf(str.charAt(3))));
            }
        }
        return new c(null, null, null);
    }

    public static /* synthetic */ c decodeUTM$default(String str, int i, Object obj) {
        if ((i & 1) != 0) {
            str = null;
        }
        return decodeUTM(str);
    }

    public static final Long decodeUserId(String str) {
        if (str != null) {
            try {
                return Long.valueOf(Long.parseLong(str, CharsKt.checkRadix(36)));
            } catch (NumberFormatException unused) {
            }
        }
        return null;
    }

    @NotNull
    public static final C0023a decodeUtmParams(@NotNull b encodedUtmParams) {
        Intrinsics.checkNotNullParameter(encodedUtmParams, "encodedUtmParams");
        return new C0023a(decodeUTM(encodedUtmParams.getUtmBlob()), decodeUserId(encodedUtmParams.getUserId()));
    }

    @NotNull
    public static final String encodeUTMParams(com.quizlet.utm.campaigns.b bVar, com.quizlet.utm.mediums.b bVar2, com.quizlet.utm.sources.b bVar3) {
        a aVar = INSTANCE;
        return C4933y.H(new Object[]{1, Character.valueOf(aVar.getEncodedChar(CAMPAIGN_MAP, bVar)), Character.valueOf(aVar.getEncodedChar(MEDIUM_MAP, bVar2)), Character.valueOf(aVar.getEncodedChar(SOURCE_MAP, bVar3))}, "", null, 62);
    }

    public static /* synthetic */ String encodeUTMParams$default(com.quizlet.utm.campaigns.b bVar, com.quizlet.utm.mediums.b bVar2, com.quizlet.utm.sources.b bVar3, int i, Object obj) {
        if ((i & 1) != 0) {
            bVar = null;
        }
        if ((i & 2) != 0) {
            bVar2 = null;
        }
        if ((i & 4) != 0) {
            bVar3 = null;
        }
        return encodeUTMParams(bVar, bVar2, bVar3);
    }

    @NotNull
    public static final b encodeUriParams(@NotNull C0023a uriParams) {
        Intrinsics.checkNotNullParameter(uriParams, "uriParams");
        Long userId = uriParams.getUserId();
        c params = uriParams.getParams();
        com.quizlet.utm.campaigns.b campaign = params != null ? params.getCampaign() : null;
        c params2 = uriParams.getParams();
        com.quizlet.utm.mediums.b medium = params2 != null ? params2.getMedium() : null;
        c params3 = uriParams.getParams();
        return generateUriValuesAsObject(campaign, medium, params3 != null ? params3.getSource() : null, userId);
    }

    @NotNull
    public static final String encodeUserId(long j) {
        String string = Long.toString(j, CharsKt.checkRadix(36));
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    @NotNull
    public static final String generateUriValues(com.quizlet.utm.campaigns.b bVar, com.quizlet.utm.mediums.b bVar2, com.quizlet.utm.sources.b bVar3, Long l) {
        b bVarGenerateUriValuesAsObject = generateUriValuesAsObject(bVar, bVar2, bVar3, l);
        return bVarGenerateUriValuesAsObject.getUserId() != null ? android.support.v4.media.session.a.m("i=", bVarGenerateUriValuesAsObject.getUserId(), "&x=", bVarGenerateUriValuesAsObject.getUtmBlob()) : AbstractC0147y.d("x=", bVarGenerateUriValuesAsObject.getUtmBlob());
    }

    public static /* synthetic */ String generateUriValues$default(com.quizlet.utm.campaigns.b bVar, com.quizlet.utm.mediums.b bVar2, com.quizlet.utm.sources.b bVar3, Long l, int i, Object obj) {
        if ((i & 1) != 0) {
            bVar = null;
        }
        if ((i & 2) != 0) {
            bVar2 = null;
        }
        if ((i & 4) != 0) {
            bVar3 = null;
        }
        if ((i & 8) != 0) {
            l = null;
        }
        return generateUriValues(bVar, bVar2, bVar3, l);
    }

    @NotNull
    public static final b generateUriValuesAsObject(com.quizlet.utm.campaigns.b bVar, com.quizlet.utm.mediums.b bVar2, com.quizlet.utm.sources.b bVar3, Long l) {
        return new b(l != null ? encodeUserId(l.longValue()) : null, encodeUTMParams(bVar, bVar2, bVar3));
    }

    public static /* synthetic */ b generateUriValuesAsObject$default(com.quizlet.utm.campaigns.b bVar, com.quizlet.utm.mediums.b bVar2, com.quizlet.utm.sources.b bVar3, Long l, int i, Object obj) {
        if ((i & 1) != 0) {
            bVar = null;
        }
        if ((i & 2) != 0) {
            bVar2 = null;
        }
        if ((i & 4) != 0) {
            bVar3 = null;
        }
        if ((i & 8) != 0) {
            l = null;
        }
        return generateUriValuesAsObject(bVar, bVar2, bVar3, l);
    }

    private final <T extends com.quizlet.utm.c> T getDecodedValue(Map<T, Character> map, Character ch) {
        Object next;
        Iterator<T> it2 = map.entrySet().iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            }
            next = it2.next();
            char cCharValue = ((Character) ((Map.Entry) next).getValue()).charValue();
            if (ch != null && cCharValue == ch.charValue()) {
                break;
            }
        }
        Map.Entry entry = (Map.Entry) next;
        if (entry != null) {
            return (T) entry.getKey();
        }
        return null;
    }

    private final <T extends com.quizlet.utm.c> char getEncodedChar(Map<T, Character> map, T t) {
        Character ch;
        if (t == null || (ch = map.get(t)) == null) {
            return '0';
        }
        return ch.charValue();
    }

    @NotNull
    public static final C0023a parseUriValues(@NotNull String serializedValues) {
        Intrinsics.checkNotNullParameter(serializedValues, "serializedValues");
        List listV = StringsKt.V(new Regex("^\\?").replace(serializedValues, ""), new char[]{'&'});
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        Iterator it2 = listV.iterator();
        while (it2.hasNext()) {
            List listSplit$default = StringsKt__StringsKt.split$default((String) it2.next(), new String[]{SimpleComparison.EQUAL_TO_OPERATION}, false, 0, 6, null);
            if (listSplit$default.size() > 1) {
                CharSequence charSequence = (CharSequence) CollectionsKt.L(listSplit$default);
                Intrinsics.checkNotNullParameter(charSequence, "<this>");
                Character chValueOf = charSequence.length() == 1 ? Character.valueOf(charSequence.charAt(0)) : null;
                List listH = CollectionsKt.H(1, listSplit$default);
                if ((chValueOf != null && chValueOf.charValue() == 'x') || (chValueOf != null && chValueOf.charValue() == 'i')) {
                    linkedHashMap.put(chValueOf, listH.size() > 1 ? CollectionsKt.S(listH, SimpleComparison.EQUAL_TO_OPERATION, null, null, null, 62) : (String) CollectionsKt.firstOrNull(listH));
                }
            }
        }
        return new C0023a(decodeUTM((String) linkedHashMap.get(Character.valueOf(UTM_GET_PARAM))), decodeUserId((String) linkedHashMap.get(Character.valueOf(USER_ID_GET_PARAM))));
    }
}
