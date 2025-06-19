package com.braze.models.theme;

import com.braze.support.JsonUtils;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class b {
    public final Integer a;
    public final Integer b;
    public final Integer c;

    public b(JSONObject buttonThemeJson) {
        Intrinsics.checkNotNullParameter(buttonThemeJson, "buttonThemeJson");
        Integer colorIntegerOrNull = JsonUtils.getColorIntegerOrNull(buttonThemeJson, "bg_color");
        Integer colorIntegerOrNull2 = JsonUtils.getColorIntegerOrNull(buttonThemeJson, "text_color");
        Integer colorIntegerOrNull3 = JsonUtils.getColorIntegerOrNull(buttonThemeJson, "border_color");
        this.a = colorIntegerOrNull;
        this.b = colorIntegerOrNull2;
        this.c = colorIntegerOrNull3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b) && Intrinsics.b(this.c, bVar.c);
    }

    public final int hashCode() {
        Integer num = this.a;
        int iHashCode = (num == null ? 0 : num.hashCode()) * 31;
        Integer num2 = this.b;
        int iHashCode2 = (iHashCode + (num2 == null ? 0 : num2.hashCode())) * 31;
        Integer num3 = this.c;
        return iHashCode2 + (num3 != null ? num3.hashCode() : 0);
    }

    public final String toString() {
        return "MessageButtonTheme(backgroundColor=" + this.a + ", textColor=" + this.b + ", borderColor=" + this.c + ')';
    }
}
