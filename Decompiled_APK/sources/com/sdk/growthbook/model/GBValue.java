package com.sdk.growthbook.model;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.U;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.C;
import kotlin.text.D;
import kotlinx.serialization.json.JsonNull;
import kotlinx.serialization.json.d;
import kotlinx.serialization.json.internal.JsonDecodingException;
import kotlinx.serialization.json.internal.x;
import kotlinx.serialization.json.k;
import kotlinx.serialization.json.l;
import kotlinx.serialization.json.v;
import kotlinx.serialization.json.y;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public abstract class GBValue {

    @NotNull
    public static final Companion Companion = new Companion(null);

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final GBValue from$GrowthBook_release(@NotNull Object anyObj) {
            Intrinsics.checkNotNullParameter(anyObj, "anyObj");
            return anyObj instanceof Boolean ? new GBBoolean(((Boolean) anyObj).booleanValue()) : anyObj instanceof String ? new GBString((String) anyObj) : anyObj instanceof Number ? new GBNumber((Number) anyObj) : Unknown.INSTANCE;
        }

        private Companion() {
        }

        /* JADX WARN: Multi-variable type inference failed */
        @NotNull
        public final GBValue from$GrowthBook_release(@NotNull k jsonElement) {
            Long lValueOf;
            Boolean bool;
            Intrinsics.checkNotNullParameter(jsonElement, "jsonElement");
            if (jsonElement instanceof y) {
                if (jsonElement instanceof JsonNull) {
                    return GBNull.INSTANCE;
                }
                y yVar = (y) jsonElement;
                if (yVar.b()) {
                    return new GBString(yVar.a());
                }
                if (l.g(yVar) != null) {
                    Intrinsics.checkNotNullParameter(yVar, "<this>");
                    try {
                        long jI = l.i(yVar);
                        if (-2147483648L <= jI && jI <= 2147483647L) {
                            return new GBNumber(Integer.valueOf((int) jI));
                        }
                        throw new NumberFormatException(yVar.a() + " is not an Int");
                    } catch (JsonDecodingException e) {
                        throw new NumberFormatException(e.getMessage());
                    }
                }
                Intrinsics.checkNotNullParameter(yVar, "<this>");
                Boolean bool2 = null;
                try {
                    lValueOf = Long.valueOf(l.i(yVar));
                } catch (JsonDecodingException unused) {
                    lValueOf = null;
                }
                if (lValueOf != null) {
                    Intrinsics.checkNotNullParameter(yVar, "<this>");
                    try {
                        return new GBNumber(Long.valueOf(l.i(yVar)));
                    } catch (JsonDecodingException e2) {
                        throw new NumberFormatException(e2.getMessage());
                    }
                }
                if (l.f(yVar) != null) {
                    Intrinsics.checkNotNullParameter(yVar, "<this>");
                    return new GBNumber(Float.valueOf(Float.parseFloat(yVar.a())));
                }
                Intrinsics.checkNotNullParameter(yVar, "<this>");
                if (C.e(yVar.a()) != null) {
                    Intrinsics.checkNotNullParameter(yVar, "<this>");
                    return new GBNumber(Double.valueOf(Double.parseDouble(yVar.a())));
                }
                Intrinsics.checkNotNullParameter(yVar, "<this>");
                String strA = yVar.a();
                String[] strArr = x.a;
                Intrinsics.checkNotNullParameter(strA, "<this>");
                if (D.l(strA, "true", true)) {
                    bool = Boolean.TRUE;
                } else {
                    bool = D.l(strA, "false", true) ? Boolean.FALSE : null;
                }
                if (bool != null) {
                    Intrinsics.checkNotNullParameter(yVar, "<this>");
                    String strA2 = yVar.a();
                    Intrinsics.checkNotNullParameter(strA2, "<this>");
                    if (D.l(strA2, "true", true)) {
                        bool2 = Boolean.TRUE;
                    } else if (D.l(strA2, "false", true)) {
                        bool2 = Boolean.FALSE;
                    }
                    if (bool2 != null) {
                        return new GBBoolean(bool2.booleanValue());
                    }
                    throw new IllegalStateException(yVar + " does not represent a Boolean");
                }
                return Unknown.INSTANCE;
            }
            if (jsonElement instanceof d) {
                Iterable iterable = (Iterable) jsonElement;
                ArrayList arrayList = new ArrayList(kotlin.collections.C.q(iterable, 10));
                Iterator it2 = iterable.iterator();
                while (it2.hasNext()) {
                    arrayList.add(GBValue.Companion.from$GrowthBook_release((k) it2.next()));
                }
                return new GBArray(arrayList);
            }
            if (jsonElement instanceof v) {
                Map map = (Map) jsonElement;
                LinkedHashMap linkedHashMap = new LinkedHashMap(U.a(map.size()));
                for (Map.Entry entry : map.entrySet()) {
                    linkedHashMap.put(entry.getKey(), GBValue.Companion.from$GrowthBook_release((k) entry.getValue()));
                }
                return new GBJson(linkedHashMap);
            }
            return Unknown.INSTANCE;
        }
    }

    @Metadata
    public static final class Unknown extends GBValue {

        @NotNull
        public static final Unknown INSTANCE = new Unknown();

        private Unknown() {
            super(null);
        }

        public boolean equals(Object obj) {
            return this == obj || (obj instanceof Unknown);
        }

        public int hashCode() {
            return 1025661968;
        }

        @NotNull
        public String toString() {
            return "Unknown";
        }
    }

    public /* synthetic */ GBValue(DefaultConstructorMarker defaultConstructorMarker) {
        this();
    }

    /* JADX WARN: Multi-variable type inference failed */
    @NotNull
    public final k gbSerialize$GrowthBook_release() {
        if (this instanceof GBNull) {
            return JsonNull.INSTANCE;
        }
        if (this instanceof GBBoolean) {
            return l.a(Boolean.valueOf(((GBBoolean) this).getValue()));
        }
        if (this instanceof GBString) {
            return l.c(((GBString) this).getValue());
        }
        if (this instanceof GBNumber) {
            return l.b(((GBNumber) this).getValue());
        }
        if (this instanceof GBArray) {
            Iterable iterable = (Iterable) this;
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(iterable, 10));
            Iterator it2 = iterable.iterator();
            while (it2.hasNext()) {
                arrayList.add(((GBValue) it2.next()).gbSerialize$GrowthBook_release());
            }
            return new d(arrayList);
        }
        if (!(this instanceof GBJson)) {
            if (this instanceof Unknown) {
                return JsonNull.INSTANCE;
            }
            throw new NoWhenBranchMatchedException();
        }
        Map map = (Map) this;
        LinkedHashMap linkedHashMap = new LinkedHashMap(U.a(map.size()));
        for (Map.Entry entry : map.entrySet()) {
            linkedHashMap.put(entry.getKey(), ((GBValue) entry.getValue()).gbSerialize$GrowthBook_release());
        }
        return new v(linkedHashMap);
    }

    public final boolean isPrimitiveValue() {
        return (this instanceof GBNull) || (this instanceof GBBoolean) || (this instanceof GBString) || (this instanceof GBNumber);
    }

    private GBValue() {
    }
}
