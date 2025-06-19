package com.snowplowanalytics.snowplow.event;

import androidx.compose.ui.node.B;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.HashMap;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends a {
    public static final /* synthetic */ int g = 0;
    public final String b;
    public final String c;
    public String d;
    public String e;
    public String f;

    public e(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        if (name.length() <= 0) {
            throw new IllegalArgumentException("Name cannot be empty");
        }
        this.b = name;
        this.c = B.f("randomUUID().toString()");
    }

    @Override // com.snowplowanalytics.snowplow.event.a
    public final Map a() {
        HashMap map = new HashMap();
        map.put("id", this.c);
        map.put("name", this.b);
        String str = this.d;
        if (str != null) {
            map.put(DBUserFields.Names.USER_UPGRADE_TYPE, str);
        }
        return map;
    }

    @Override // com.snowplowanalytics.snowplow.event.a
    public final String b() {
        return "iglu:com.snowplowanalytics.mobile/screen_view/jsonschema/1-0-0";
    }
}
