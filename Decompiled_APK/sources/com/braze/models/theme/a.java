package com.braze.models.theme;

import com.braze.support.JsonUtils;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class a {
    public final Integer a;
    public final Integer b;
    public final Integer c;
    public final Integer d;
    public final Integer e;
    public final Integer f;
    public final Integer g;

    public a(JSONObject messageThemeJson) {
        Intrinsics.checkNotNullParameter(messageThemeJson, "messageThemeJson");
        Integer colorIntegerOrNull = JsonUtils.getColorIntegerOrNull(messageThemeJson, "bg_color");
        Integer colorIntegerOrNull2 = JsonUtils.getColorIntegerOrNull(messageThemeJson, "text_color");
        Integer colorIntegerOrNull3 = JsonUtils.getColorIntegerOrNull(messageThemeJson, "close_btn_color");
        Integer colorIntegerOrNull4 = JsonUtils.getColorIntegerOrNull(messageThemeJson, "icon_color");
        Integer colorIntegerOrNull5 = JsonUtils.getColorIntegerOrNull(messageThemeJson, "icon_bg_color");
        Integer colorIntegerOrNull6 = JsonUtils.getColorIntegerOrNull(messageThemeJson, "header_text_color");
        Integer colorIntegerOrNull7 = JsonUtils.getColorIntegerOrNull(messageThemeJson, "frame_color");
        this.a = colorIntegerOrNull;
        this.b = colorIntegerOrNull2;
        this.c = colorIntegerOrNull3;
        this.d = colorIntegerOrNull4;
        this.e = colorIntegerOrNull5;
        this.f = colorIntegerOrNull6;
        this.g = colorIntegerOrNull7;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && Intrinsics.b(this.c, aVar.c) && Intrinsics.b(this.d, aVar.d) && Intrinsics.b(this.e, aVar.e) && Intrinsics.b(this.f, aVar.f) && Intrinsics.b(this.g, aVar.g);
    }

    public final int hashCode() {
        Integer num = this.a;
        int iHashCode = (num == null ? 0 : num.hashCode()) * 31;
        Integer num2 = this.b;
        int iHashCode2 = (iHashCode + (num2 == null ? 0 : num2.hashCode())) * 31;
        Integer num3 = this.c;
        int iHashCode3 = (iHashCode2 + (num3 == null ? 0 : num3.hashCode())) * 31;
        Integer num4 = this.d;
        int iHashCode4 = (iHashCode3 + (num4 == null ? 0 : num4.hashCode())) * 31;
        Integer num5 = this.e;
        int iHashCode5 = (iHashCode4 + (num5 == null ? 0 : num5.hashCode())) * 31;
        Integer num6 = this.f;
        int iHashCode6 = (iHashCode5 + (num6 == null ? 0 : num6.hashCode())) * 31;
        Integer num7 = this.g;
        return iHashCode6 + (num7 != null ? num7.hashCode() : 0);
    }

    public final String toString() {
        return "InAppMessageTheme(backgroundColor=" + this.a + ", textColor=" + this.b + ", closeButtonColor=" + this.c + ", iconColor=" + this.d + ", iconBackgroundColor=" + this.e + ", headerTextColor=" + this.f + ", frameColor=" + this.g + ')';
    }
}
