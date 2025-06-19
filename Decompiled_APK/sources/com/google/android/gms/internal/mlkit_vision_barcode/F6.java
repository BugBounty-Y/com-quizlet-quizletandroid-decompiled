package com.google.android.gms.internal.mlkit_vision_barcode;

import com.quizlet.db.data.models.persisted.DBFolder;
import com.quizlet.db.data.models.persisted.DBUser;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class F6 {
    /* JADX WARN: Removed duplicated region for block: B:19:0x008d  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0097  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.snowplowanalytics.snowplow.event.e a(android.app.Activity r7) throws java.lang.IllegalAccessException, java.lang.IllegalArgumentException {
        /*
            java.lang.String r0 = "activity"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r0)
            java.lang.String r0 = r7.getLocalClassName()
            java.lang.String r1 = "activity.localClassName"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r1)
            java.lang.String r1 = "format(format, *args)"
            java.lang.String r2 = "TAG"
            java.lang.String r3 = "e"
            java.lang.Class r4 = r7.getClass()
            r5 = 1
            java.lang.String r6 = "snowplowScreenId"
            java.lang.reflect.Field r6 = r4.getField(r6)     // Catch: java.lang.Exception -> L2a java.lang.NoSuchFieldException -> L2c
            java.lang.Object r7 = r6.get(r7)     // Catch: java.lang.Exception -> L2a java.lang.NoSuchFieldException -> L2c
            boolean r6 = r7 instanceof java.lang.String     // Catch: java.lang.Exception -> L2a java.lang.NoSuchFieldException -> L2c
            if (r6 == 0) goto L2e
            java.lang.String r7 = (java.lang.String) r7     // Catch: java.lang.Exception -> L2a java.lang.NoSuchFieldException -> L2c
            goto L83
        L2a:
            r7 = move-exception
            goto L4d
        L2c:
            r7 = move-exception
            goto L6a
        L2e:
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, r2)     // Catch: java.lang.Exception -> L2a java.lang.NoSuchFieldException -> L2c
            java.lang.String r7 = "The value of field `snowplowScreenId` on Activity `%s` has to be a String."
            java.lang.String r6 = r4.getSimpleName()     // Catch: java.lang.Exception -> L2a java.lang.NoSuchFieldException -> L2c
            java.lang.Object[] r6 = new java.lang.Object[]{r6}     // Catch: java.lang.Exception -> L2a java.lang.NoSuchFieldException -> L2c
            java.lang.Object[] r6 = java.util.Arrays.copyOf(r6, r5)     // Catch: java.lang.Exception -> L2a java.lang.NoSuchFieldException -> L2c
            java.lang.String r7 = java.lang.String.format(r7, r6)     // Catch: java.lang.Exception -> L2a java.lang.NoSuchFieldException -> L2c
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r7, r1)     // Catch: java.lang.Exception -> L2a java.lang.NoSuchFieldException -> L2c
            r6 = 0
            java.lang.Object[] r6 = new java.lang.Object[r6]     // Catch: java.lang.Exception -> L2a java.lang.NoSuchFieldException -> L2c
            com.snowplowanalytics.core.tracker.e.b(r3, r7, r6)     // Catch: java.lang.Exception -> L2a java.lang.NoSuchFieldException -> L2c
            goto L82
        L4d:
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, r2)
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            java.lang.String r2 = "Error retrieving value of field `snowplowScreenId`: "
            r1.<init>(r2)
            java.lang.String r2 = r7.getMessage()
            r1.append(r2)
            java.lang.String r1 = r1.toString()
            java.lang.Object[] r7 = new java.lang.Object[]{r7}
            com.snowplowanalytics.core.tracker.e.b(r3, r1, r7)
            goto L82
        L6a:
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, r2)
            java.lang.String r2 = r4.getSimpleName()
            java.lang.Object[] r2 = new java.lang.Object[]{r2}
            java.lang.String r4 = "Field `snowplowScreenId` not found on Activity `%s`."
            java.lang.String r1 = androidx.compose.animation.d0.s(r2, r5, r4, r1)
            java.lang.Object[] r7 = new java.lang.Object[]{r7}
            com.snowplowanalytics.core.tracker.e.a(r3, r1, r7)
        L82:
            r7 = 0
        L83:
            if (r0 == 0) goto L8d
            int r1 = r0.length()
            if (r1 <= 0) goto L8d
            r1 = r0
            goto L99
        L8d:
            if (r7 == 0) goto L97
            int r1 = r7.length()
            if (r1 <= 0) goto L97
            r1 = r7
            goto L99
        L97:
            java.lang.String r1 = "Unknown"
        L99:
            com.snowplowanalytics.snowplow.event.e r2 = new com.snowplowanalytics.snowplow.event.e
            r2.<init>(r1)
            r2.e = r0
            r2.f = r7
            r2.d = r0
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.F6.a(android.app.Activity):com.snowplowanalytics.snowplow.event.e");
    }

    public static final com.quizlet.features.infra.models.folders.a b(DBFolder dBFolder) {
        Intrinsics.checkNotNullParameter(dBFolder, "<this>");
        long id = dBFolder.getId();
        String name = dBFolder.getName();
        Intrinsics.checkNotNullExpressionValue(name, "getName(...)");
        long personId = dBFolder.getPersonId();
        DBUser person = dBFolder.getPerson();
        return new com.quizlet.features.infra.models.folders.a(id, name, personId, person != null ? C6.b(person) : null);
    }
}
