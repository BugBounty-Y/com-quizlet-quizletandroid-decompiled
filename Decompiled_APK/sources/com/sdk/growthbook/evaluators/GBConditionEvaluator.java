package com.sdk.growthbook.evaluators;

import com.quizlet.ui.compose.C4830x;
import com.sdk.growthbook.model.GBArray;
import com.sdk.growthbook.model.GBBoolean;
import com.sdk.growthbook.model.GBJson;
import com.sdk.growthbook.model.GBNull;
import com.sdk.growthbook.model.GBNumber;
import com.sdk.growthbook.model.GBString;
import com.sdk.growthbook.model.GBValue;
import com.sdk.growthbook.utils.GBUtils;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.C;
import kotlin.text.D;
import kotlin.text.Regex;
import kotlin.text.StringsKt;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBConditionEvaluator {
    private final boolean arraysEqual(GBArray gBArray, GBArray gBArray2) {
        if (gBArray.size() != gBArray2.size()) {
            return false;
        }
        int size = gBArray.size();
        for (int i = 0; i < size; i++) {
            if (!Intrinsics.b(gBArray.get(i), gBArray2.get(i))) {
                return false;
            }
        }
        return true;
    }

    private final String asKey(GBValue gBValue) {
        return gBValue instanceof GBString ? ((GBString) gBValue).getValue() : gBValue.toString();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final boolean comparisonTemplate(GBValue gBValue, GBValue gBValue2, Function2<? super String, ? super String, Boolean> function2, Function2<? super Double, ? super Double, Boolean> function22) {
        boolean z = gBValue instanceof GBString;
        if (!z || !(gBValue2 instanceof GBString)) {
            return ((Boolean) function22.invoke(Double.valueOf(gBValue != null ? tryRetrieveDouble(gBValue) : 0.0d), Double.valueOf(tryRetrieveDouble(gBValue2)))).booleanValue();
        }
        GBString gBString = z ? (GBString) gBValue : null;
        String value = gBString != null ? gBString.getValue() : null;
        if (value == null) {
            value = "";
        }
        GBString gBString2 = gBValue2 instanceof GBString ? (GBString) gBValue2 : null;
        String value2 = gBString2 != null ? gBString2.getValue() : null;
        return ((Boolean) function2.invoke(value, value2 != null ? value2 : "")).booleanValue();
    }

    /* JADX WARN: Multi-variable type inference failed */
    private final boolean elemMatch(GBValue gBValue, GBValue gBValue2, Map<String, ? extends GBValue> map) {
        if (!(gBValue instanceof GBArray)) {
            return false;
        }
        Iterator<GBValue> it2 = ((GBArray) gBValue).iterator();
        while (it2.hasNext()) {
            GBValue next = it2.next();
            Map<String, ? extends GBValue> map2 = next instanceof GBJson ? new HashMap<>((Map) next) : U.b(new Pair("value", next));
            boolean z = gBValue2 instanceof GBJson;
            if (!z || !isOperatorObject((GBJson) gBValue2)) {
                GBJson gBJson = z ? (GBJson) gBValue2 : null;
                if (gBJson == null) {
                    gBJson = new GBJson(V.c());
                }
                if (evalCondition(map2, gBJson, map)) {
                    return true;
                }
            } else if (evalConditionValue(gBValue2, next, map)) {
                return true;
            }
        }
        return false;
    }

    private final boolean evalAnd(Map<String, ? extends GBValue> map, GBArray gBArray, Map<String, ? extends GBValue> map2) {
        Iterator<GBValue> it2 = gBArray.iterator();
        while (it2.hasNext()) {
            GBValue next = it2.next();
            GBJson gBJson = next instanceof GBJson ? (GBJson) next : null;
            if (gBJson == null || !evalCondition(map, gBJson, map2)) {
                return false;
            }
        }
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean evalOperatorCondition$lambda$0(String actual, String expected) {
        Intrinsics.checkNotNullParameter(actual, "actual");
        Intrinsics.checkNotNullParameter(expected, "expected");
        return actual.compareTo(expected) < 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean evalOperatorCondition$lambda$1(double d, double d2) {
        return d < d2;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean evalOperatorCondition$lambda$2(String actual, String expected) {
        Intrinsics.checkNotNullParameter(actual, "actual");
        Intrinsics.checkNotNullParameter(expected, "expected");
        return actual.compareTo(expected) <= 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean evalOperatorCondition$lambda$3(double d, double d2) {
        return d <= d2;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean evalOperatorCondition$lambda$4(String actual, String expected) {
        Intrinsics.checkNotNullParameter(actual, "actual");
        Intrinsics.checkNotNullParameter(expected, "expected");
        return actual.compareTo(expected) > 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean evalOperatorCondition$lambda$5(double d, double d2) {
        return d > d2;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean evalOperatorCondition$lambda$6(String actual, String expected) {
        Intrinsics.checkNotNullParameter(actual, "actual");
        Intrinsics.checkNotNullParameter(expected, "expected");
        return actual.compareTo(expected) >= 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean evalOperatorCondition$lambda$7(double d, double d2) {
        return d >= d2;
    }

    private final boolean evalOr(Map<String, ? extends GBValue> map, GBArray gBArray, Map<String, ? extends GBValue> map2) {
        if (gBArray.isEmpty()) {
            return true;
        }
        Iterator<GBValue> it2 = gBArray.iterator();
        while (it2.hasNext()) {
            GBValue next = it2.next();
            GBJson gBJson = next instanceof GBJson ? (GBJson) next : null;
            if (gBJson == null) {
                return false;
            }
            if (evalCondition(map, gBJson, map2)) {
                return true;
            }
        }
        return false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    private final boolean isIn(GBValue gBValue, GBArray gBArray) {
        if (!(gBValue instanceof GBArray)) {
            return gBArray.contains((Object) gBValue);
        }
        if (((GBArray) gBValue).size() == 0) {
            return false;
        }
        for (GBValue gBValue2 : (Iterable) gBValue) {
            if (getType(gBValue2) == GBAttributeType.GbString || getType(gBValue2) == GBAttributeType.GbBoolean || getType(gBValue2) == GBAttributeType.GbNumber) {
                if (gBArray.contains((Object) gBValue2)) {
                    return true;
                }
            }
        }
        return false;
    }

    private final double tryRetrieveDouble(GBValue gBValue) {
        Double dE;
        if (gBValue instanceof GBNumber) {
            return ((GBNumber) gBValue).getValue().doubleValue();
        }
        if (!(gBValue instanceof GBString) || (dE = C.e(((GBString) gBValue).getValue())) == null) {
            return 0.0d;
        }
        return dE.doubleValue();
    }

    /* JADX WARN: Removed duplicated region for block: B:61:0x009d A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:78:0x0012 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean evalCondition(@org.jetbrains.annotations.NotNull java.util.Map<java.lang.String, ? extends com.sdk.growthbook.model.GBValue> r7, @org.jetbrains.annotations.NotNull com.sdk.growthbook.model.GBJson r8, java.util.Map<java.lang.String, ? extends com.sdk.growthbook.model.GBValue> r9) {
        /*
            r6 = this;
            java.lang.String r0 = "attributes"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r0)
            java.lang.String r0 = "conditionObj"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r0)
            java.util.Set r0 = r8.entrySet()
            java.util.Iterator r0 = r0.iterator()
        L12:
            boolean r1 = r0.hasNext()
            if (r1 == 0) goto Lb2
            java.lang.Object r1 = r0.next()
            java.util.Map$Entry r1 = (java.util.Map.Entry) r1
            java.lang.Object r2 = r1.getKey()
            java.lang.String r2 = (java.lang.String) r2
            java.lang.Object r1 = r1.getValue()
            com.sdk.growthbook.model.GBValue r1 = (com.sdk.growthbook.model.GBValue) r1
            int r3 = r2.hashCode()
            r4 = 0
            r5 = 0
            switch(r3) {
                case 38151: goto L8b;
                case 1169203: goto L6e;
                case 1181741: goto L51;
                case 1181743: goto L34;
                default: goto L33;
            }
        L33:
            goto L93
        L34:
            java.lang.String r3 = "$not"
            boolean r3 = r2.equals(r3)
            if (r3 != 0) goto L3d
            goto L93
        L3d:
            java.lang.Object r1 = r8.get(r2)
            boolean r2 = r1 instanceof com.sdk.growthbook.model.GBJson
            if (r2 == 0) goto L48
            r4 = r1
            com.sdk.growthbook.model.GBJson r4 = (com.sdk.growthbook.model.GBJson) r4
        L48:
            if (r4 == 0) goto L12
            boolean r1 = r6.evalCondition(r7, r4, r9)
            if (r1 == 0) goto L12
            return r5
        L51:
            java.lang.String r3 = "$nor"
            boolean r3 = r2.equals(r3)
            if (r3 != 0) goto L5a
            goto L93
        L5a:
            java.lang.Object r1 = r8.get(r2)
            boolean r2 = r1 instanceof com.sdk.growthbook.model.GBArray
            if (r2 == 0) goto L65
            r4 = r1
            com.sdk.growthbook.model.GBArray r4 = (com.sdk.growthbook.model.GBArray) r4
        L65:
            if (r4 == 0) goto L12
            boolean r1 = r6.evalOr(r7, r4, r9)
            if (r1 == 0) goto L12
            return r5
        L6e:
            java.lang.String r3 = "$and"
            boolean r3 = r2.equals(r3)
            if (r3 != 0) goto L77
            goto L93
        L77:
            java.lang.Object r1 = r8.get(r2)
            boolean r2 = r1 instanceof com.sdk.growthbook.model.GBArray
            if (r2 == 0) goto L82
            r4 = r1
            com.sdk.growthbook.model.GBArray r4 = (com.sdk.growthbook.model.GBArray) r4
        L82:
            if (r4 == 0) goto L12
            boolean r1 = r6.evalAnd(r7, r4, r9)
            if (r1 != 0) goto L12
            return r5
        L8b:
            java.lang.String r3 = "$or"
            boolean r3 = r2.equals(r3)
            if (r3 != 0) goto L9e
        L93:
            com.sdk.growthbook.model.GBValue r2 = r6.getPath(r7, r2)
            boolean r1 = r6.evalConditionValue(r1, r2, r9)
            if (r1 != 0) goto L12
            return r5
        L9e:
            java.lang.Object r1 = r8.get(r2)
            boolean r2 = r1 instanceof com.sdk.growthbook.model.GBArray
            if (r2 == 0) goto La9
            r4 = r1
            com.sdk.growthbook.model.GBArray r4 = (com.sdk.growthbook.model.GBArray) r4
        La9:
            if (r4 == 0) goto L12
            boolean r1 = r6.evalOr(r7, r4, r9)
            if (r1 != 0) goto L12
            return r5
        Lb2:
            r7 = 1
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.sdk.growthbook.evaluators.GBConditionEvaluator.evalCondition(java.util.Map, com.sdk.growthbook.model.GBJson, java.util.Map):boolean");
    }

    public final boolean evalConditionValue(@NotNull GBValue conditionValue, GBValue gBValue, Map<String, ? extends GBValue> map) {
        Intrinsics.checkNotNullParameter(conditionValue, "conditionValue");
        if (conditionValue.isPrimitiveValue() && (gBValue == null || gBValue.isPrimitiveValue())) {
            return conditionValue.equals(gBValue);
        }
        if (conditionValue.isPrimitiveValue() && gBValue == null) {
            return false;
        }
        if (conditionValue instanceof GBArray) {
            if (gBValue instanceof GBArray) {
                return arraysEqual((GBArray) conditionValue, (GBArray) gBValue);
            }
            return false;
        }
        if (!(conditionValue instanceof GBJson)) {
            return true;
        }
        GBJson gBJson = (GBJson) conditionValue;
        if (!isOperatorObject(gBJson)) {
            if (gBValue != null) {
                return conditionValue.equals(gBValue);
            }
            return false;
        }
        for (String str : gBJson.keySet()) {
            Object obj = gBJson.get((Object) str);
            Intrinsics.d(obj);
            if (!evalOperatorCondition(str, gBValue, (GBValue) obj, map)) {
                return false;
            }
        }
        return true;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Multi-variable type inference failed */
    public final boolean evalOperatorCondition(@NotNull String operator, GBValue gBValue, @NotNull GBValue conditionValue, Map<String, ? extends GBValue> map) {
        String value;
        String value2;
        Intrinsics.checkNotNullParameter(operator, "operator");
        Intrinsics.checkNotNullParameter(conditionValue, "conditionValue");
        if (Intrinsics.b(operator, "$type")) {
            GBString gBString = conditionValue instanceof GBString ? (GBString) conditionValue : null;
            return Intrinsics.b(getType(gBValue).toString(), gBString != null ? gBString.getValue() : null);
        }
        if (Intrinsics.b(operator, "$not")) {
            return !evalConditionValue(conditionValue, gBValue, map);
        }
        if (Intrinsics.b(operator, "$exists")) {
            GBBoolean gBBoolean = conditionValue instanceof GBBoolean ? (GBBoolean) conditionValue : null;
            boolean z = gBValue == null || (gBValue instanceof GBNull);
            if (gBBoolean != null && !gBBoolean.getValue() && z) {
                return true;
            }
            boolean z2 = gBBoolean != null && gBBoolean.getValue();
            boolean z3 = gBValue != null;
            boolean z4 = gBValue instanceof GBNull;
            if (z2 && z3 && !z4) {
                return true;
            }
        }
        if (!(conditionValue instanceof GBArray)) {
            if (!(gBValue instanceof GBArray)) {
                if (gBValue != null && gBValue.isPrimitiveValue()) {
                    GBString gBString2 = conditionValue instanceof GBString ? (GBString) conditionValue : null;
                    GBString gBString3 = gBValue instanceof GBString ? (GBString) gBValue : null;
                    GBUtils.Companion companion = GBUtils.Companion;
                    String value3 = gBString2 != null ? gBString2.getValue() : null;
                    String str = "";
                    if (value3 == null) {
                        value3 = "";
                    }
                    String strPaddedVersionString = companion.paddedVersionString(value3);
                    String str2 = "0";
                    if (gBString3 == null || (value = gBString3.getValue()) == null) {
                        value = "0";
                    }
                    String strPaddedVersionString2 = companion.paddedVersionString(value);
                    switch (operator.hashCode()) {
                        case 37840:
                            if (operator.equals("$eq")) {
                                return Intrinsics.b(gBString3, gBString2);
                            }
                            break;
                        case 37905:
                            if (operator.equals("$gt")) {
                                return comparisonTemplate(gBValue, conditionValue, new C4830x(5, (byte) 0), new C4830x(6, (byte) 0));
                            }
                            break;
                        case 38060:
                            if (operator.equals("$lt")) {
                                return comparisonTemplate(gBValue, conditionValue, new C4830x(1, (byte) 0), new C4830x(2, (byte) 0));
                            }
                            break;
                        case 38107:
                            if (operator.equals("$ne")) {
                                return !Intrinsics.b(conditionValue, gBValue);
                            }
                            break;
                        case 1175156:
                            if (operator.equals("$gte")) {
                                return comparisonTemplate(gBValue, conditionValue, new C4830x(7, (byte) 0), new C4830x(8, (byte) 0));
                            }
                            break;
                        case 1179961:
                            if (operator.equals("$lte")) {
                                return comparisonTemplate(gBValue, conditionValue, new C4830x(3, (byte) 0), new C4830x(4, (byte) 0));
                            }
                            break;
                        case 1189118:
                            if (operator.equals("$veq")) {
                                return Intrinsics.b(strPaddedVersionString2, strPaddedVersionString);
                            }
                            break;
                        case 1189183:
                            return operator.equals("$vgt") && strPaddedVersionString2.compareTo(strPaddedVersionString) > 0;
                        case 1189338:
                            return operator.equals("$vlt") && strPaddedVersionString2.compareTo(strPaddedVersionString) < 0;
                        case 1189385:
                            if (operator.equals("$vne")) {
                                return !Intrinsics.b(strPaddedVersionString2, strPaddedVersionString);
                            }
                            break;
                        case 36864774:
                            return operator.equals("$vgte") && strPaddedVersionString2.compareTo(strPaddedVersionString) >= 0;
                        case 36869579:
                            return operator.equals("$vlte") && strPaddedVersionString2.compareTo(strPaddedVersionString) <= 0;
                        case 233551798:
                            if (operator.equals("$inGroup")) {
                                Object obj = map != null ? (GBValue) map.get(asKey(conditionValue)) : null;
                                GBArray gBArray = obj instanceof GBArray ? (GBArray) obj : null;
                                if (gBArray == null) {
                                    gBArray = new GBArray(K.a);
                                }
                                return isIn(gBValue, gBArray);
                            }
                            break;
                        case 417740075:
                            if (operator.equals("$notInGroup")) {
                                Object obj2 = map != null ? (GBValue) map.get(asKey(conditionValue)) : null;
                                GBArray gBArray2 = obj2 instanceof GBArray ? (GBArray) obj2 : null;
                                if (gBArray2 == null) {
                                    gBArray2 = new GBArray(K.a);
                                }
                                return !isIn(gBValue, gBArray2);
                            }
                            break;
                        case 1139041955:
                            if (operator.equals("$regex")) {
                                try {
                                    String value4 = gBString2 != null ? gBString2.getValue() : null;
                                    if (value4 != null) {
                                        str = value4;
                                    }
                                    Regex regex = new Regex(str);
                                    if (gBString3 != null && (value2 = gBString3.getValue()) != null) {
                                        str2 = value2;
                                    }
                                    return regex.a(str2);
                                } catch (Throwable unused) {
                                    return false;
                                }
                            }
                            break;
                    }
                }
            } else {
                if (Intrinsics.b(operator, "$elemMatch")) {
                    return elemMatch(gBValue, conditionValue, map);
                }
                if (Intrinsics.b(operator, "$size")) {
                    return evalConditionValue(conditionValue, new GBNumber(Integer.valueOf(((GBArray) gBValue).size())), map);
                }
            }
        } else {
            int iHashCode = operator.hashCode();
            if (iHashCode != 37961) {
                if (iHashCode == 1169149) {
                    if (!operator.equals("$all") || !(gBValue instanceof GBArray)) {
                        return false;
                    }
                    Iterator<GBValue> it2 = ((GBArray) conditionValue).iterator();
                    while (it2.hasNext()) {
                        GBValue next = it2.next();
                        Iterator<GBValue> it3 = ((GBArray) gBValue).iterator();
                        boolean z5 = false;
                        while (it3.hasNext()) {
                            if (evalConditionValue(next, it3.next(), map)) {
                                z5 = true;
                            }
                        }
                        if (!z5) {
                            return false;
                        }
                    }
                    return true;
                }
                if (iHashCode == 1181551 && operator.equals("$nin")) {
                    return gBValue instanceof GBArray ? !isIn(gBValue, (GBArray) conditionValue) : !CollectionsKt.F((Iterable) conditionValue, gBValue);
                }
            } else if (operator.equals("$in")) {
                return gBValue instanceof GBArray ? isIn(gBValue, (GBArray) conditionValue) : CollectionsKt.F((Iterable) conditionValue, gBValue);
            }
        }
        return false;
    }

    @NotNull
    public final GBValue getPath(@NotNull Map<String, ? extends GBValue> attributes, @NotNull String key) {
        ArrayList arrayList;
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(key, "key");
        if (StringsKt.G(key, ".", false)) {
            List listSplit$default = StringsKt__StringsKt.split$default(key, new String[]{"."}, false, 0, 6, null);
            Intrinsics.e(listSplit$default, "null cannot be cast to non-null type java.util.ArrayList<kotlin.String>");
            arrayList = (ArrayList) listSplit$default;
        } else {
            ArrayList arrayList2 = new ArrayList();
            arrayList2.add(key);
            arrayList = arrayList2;
        }
        GBValue gBValue = attributes.get(arrayList.get(0));
        if (gBValue == null) {
            gBValue = GBNull.INSTANCE;
        }
        for (Object obj : arrayList.subList(1, arrayList.size())) {
            Intrinsics.checkNotNullExpressionValue(obj, "next(...)");
            String str = (String) obj;
            if ((gBValue instanceof GBJson) && (gBValue = (GBValue) ((GBJson) gBValue).get((Object) str)) == null) {
                gBValue = GBNull.INSTANCE;
            }
        }
        return gBValue;
    }

    @NotNull
    public final GBAttributeType getType(GBValue gBValue) {
        return Intrinsics.b(gBValue, GBNull.INSTANCE) ? GBAttributeType.GbNull : (gBValue == null || !gBValue.isPrimitiveValue()) ? gBValue instanceof GBArray ? GBAttributeType.GbArray : gBValue instanceof GBJson ? GBAttributeType.GbObject : GBAttributeType.GbUnknown : gBValue instanceof GBString ? GBAttributeType.GbString : gBValue instanceof GBBoolean ? GBAttributeType.GbBoolean : gBValue instanceof GBNumber ? GBAttributeType.GbNumber : GBAttributeType.GbUnknown;
    }

    public final boolean isOperatorObject(@NotNull GBJson obj) {
        Intrinsics.checkNotNullParameter(obj, "obj");
        if (!obj.keySet().isEmpty()) {
            Iterator<String> it2 = obj.keySet().iterator();
            while (it2.hasNext()) {
                if (!D.r(it2.next(), "$", false)) {
                }
            }
            return true;
        }
        return false;
    }
}
