package com.google.firebase.crashlytics.internal.settings;

import androidx.compose.ui.node.B;
import com.google.android.gms.internal.mlkit_vision_barcode.E6;
import com.google.firebase.crashlytics.internal.common.v;
import com.quizlet.db.data.models.persisted.fields.DBAnswerFields;
import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d implements com.snowplowanalytics.core.statemachine.d {
    public String a;
    public String b;
    public String c;
    public String d;
    public int e;
    public final String f;
    public final String g;
    public Object h;
    public Object i;

    public d(String firstEventId, String firstEventTimestamp, String sessionId, String str, int i, String userId, String storage, Integer num, Long l) {
        Intrinsics.checkNotNullParameter(firstEventId, "firstEventId");
        Intrinsics.checkNotNullParameter(firstEventTimestamp, "firstEventTimestamp");
        Intrinsics.checkNotNullParameter(sessionId, "sessionId");
        Intrinsics.checkNotNullParameter(userId, "userId");
        Intrinsics.checkNotNullParameter(storage, "storage");
        this.a = firstEventId;
        this.b = firstEventTimestamp;
        this.c = sessionId;
        this.d = str;
        this.e = i;
        this.f = userId;
        this.g = storage;
        this.h = num;
        this.i = l;
    }

    public HashMap a() {
        HashMap map = new HashMap();
        map.put("firstEventId", this.a);
        map.put("firstEventTimestamp", this.b);
        map.put(DBAnswerFields.Names.SESSION_ID, this.c);
        map.put("previousSessionId", this.d);
        map.put("sessionIndex", Integer.valueOf(this.e));
        map.put("userId", this.f);
        map.put("storageMechanism", this.g);
        Integer num = (Integer) this.h;
        if (num != null) {
            map.put("eventIndex", Integer.valueOf(num.intValue()));
        }
        return map;
    }

    public void b(long j, String eventId) {
        Intrinsics.checkNotNullParameter(eventId, "eventId");
        this.d = this.c;
        this.c = B.f("randomUUID().toString()");
        this.e++;
        this.h = 0;
        this.a = eventId;
        this.b = E6.c(j);
        this.i = Long.valueOf(System.currentTimeMillis());
    }

    public d(String str, String str2, String str3, String str4, v vVar, String str5, String str6, String str7, int i) {
        this.a = str;
        this.b = str2;
        this.c = str3;
        this.d = str4;
        this.i = vVar;
        this.f = str5;
        this.g = str6;
        this.h = str7;
        this.e = i;
    }
}
