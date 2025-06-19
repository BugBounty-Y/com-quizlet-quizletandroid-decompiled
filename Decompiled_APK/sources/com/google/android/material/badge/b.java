package com.google.android.material.badge;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.content.res.XmlResourceParser;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.util.Xml;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4;
import com.google.android.material.internal.p;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.IOException;
import java.util.Locale;
import org.xmlpull.v1.XmlPullParserException;

/* loaded from: classes2.dex */
public final class b {
    public final BadgeState$State a;
    public final BadgeState$State b = new BadgeState$State();
    public final float c;
    public final float d;
    public final float e;
    public final float f;
    public final float g;
    public final float h;
    public final int i;
    public final int j;
    public final int k;

    public b(Context context) throws XmlPullParserException, Resources.NotFoundException, IOException {
        AttributeSet attributeSet;
        int styleAttribute;
        int next;
        BadgeState$State badgeState$State = new BadgeState$State();
        int i = badgeState$State.a;
        if (i != 0) {
            try {
                XmlResourceParser xml = context.getResources().getXml(i);
                do {
                    next = xml.next();
                    if (next == 2) {
                        break;
                    }
                } while (next != 1);
                if (next != 2) {
                    throw new XmlPullParserException("No start tag found");
                }
                if (!TextUtils.equals(xml.getName(), "badge")) {
                    throw new XmlPullParserException("Must have a <" + ((Object) "badge") + "> start tag");
                }
                AttributeSet attributeSetAsAttributeSet = Xml.asAttributeSet(xml);
                attributeSet = attributeSetAsAttributeSet;
                styleAttribute = attributeSetAsAttributeSet.getStyleAttribute();
            } catch (IOException | XmlPullParserException e) {
                Resources.NotFoundException notFoundException = new Resources.NotFoundException("Can't load badge resource ID #0x" + Integer.toHexString(i));
                notFoundException.initCause(e);
                throw notFoundException;
            }
        } else {
            attributeSet = null;
            styleAttribute = 0;
        }
        TypedArray typedArrayL = p.l(context, attributeSet, com.google.android.material.a.c, R.attr.badgeStyle, styleAttribute == 0 ? R.style.Widget_MaterialComponents_Badge : styleAttribute, new int[0]);
        Resources resources = context.getResources();
        this.c = typedArrayL.getDimensionPixelSize(4, -1);
        this.i = context.getResources().getDimensionPixelSize(R.dimen.mtrl_badge_horizontal_edge_offset);
        this.j = context.getResources().getDimensionPixelSize(R.dimen.mtrl_badge_text_horizontal_edge_offset);
        this.d = typedArrayL.getDimensionPixelSize(14, -1);
        this.e = typedArrayL.getDimension(12, resources.getDimension(R.dimen.m3_badge_size));
        this.g = typedArrayL.getDimension(17, resources.getDimension(R.dimen.m3_badge_with_text_size));
        this.f = typedArrayL.getDimension(3, resources.getDimension(R.dimen.m3_badge_size));
        this.h = typedArrayL.getDimension(13, resources.getDimension(R.dimen.m3_badge_with_text_size));
        this.k = typedArrayL.getInt(24, 1);
        BadgeState$State badgeState$State2 = this.b;
        int i2 = badgeState$State.i;
        badgeState$State2.i = i2 == -2 ? 255 : i2;
        int i3 = badgeState$State.k;
        if (i3 != -2) {
            badgeState$State2.k = i3;
        } else if (typedArrayL.hasValue(23)) {
            this.b.k = typedArrayL.getInt(23, 0);
        } else {
            this.b.k = -1;
        }
        String str = badgeState$State.j;
        if (str != null) {
            this.b.j = str;
        } else if (typedArrayL.hasValue(7)) {
            this.b.j = typedArrayL.getString(7);
        }
        BadgeState$State badgeState$State3 = this.b;
        badgeState$State3.o = badgeState$State.o;
        CharSequence charSequence = badgeState$State.p;
        badgeState$State3.p = charSequence == null ? context.getString(R.string.mtrl_badge_numberless_content_description) : charSequence;
        BadgeState$State badgeState$State4 = this.b;
        int i4 = badgeState$State.q;
        badgeState$State4.q = i4 == 0 ? R.plurals.mtrl_badge_content_description : i4;
        int i5 = badgeState$State.r;
        badgeState$State4.r = i5 == 0 ? R.string.mtrl_exceed_max_badge_number_content_description : i5;
        Boolean bool = badgeState$State.t;
        badgeState$State4.t = Boolean.valueOf(bool == null || bool.booleanValue());
        BadgeState$State badgeState$State5 = this.b;
        int i6 = badgeState$State.l;
        badgeState$State5.l = i6 == -2 ? typedArrayL.getInt(21, -2) : i6;
        BadgeState$State badgeState$State6 = this.b;
        int i7 = badgeState$State.m;
        badgeState$State6.m = i7 == -2 ? typedArrayL.getInt(22, -2) : i7;
        BadgeState$State badgeState$State7 = this.b;
        Integer num = badgeState$State.e;
        badgeState$State7.e = Integer.valueOf(num == null ? typedArrayL.getResourceId(5, R.style.ShapeAppearance_M3_Sys_Shape_Corner_Full) : num.intValue());
        BadgeState$State badgeState$State8 = this.b;
        Integer num2 = badgeState$State.f;
        badgeState$State8.f = Integer.valueOf(num2 == null ? typedArrayL.getResourceId(6, 0) : num2.intValue());
        BadgeState$State badgeState$State9 = this.b;
        Integer num3 = badgeState$State.g;
        badgeState$State9.g = Integer.valueOf(num3 == null ? typedArrayL.getResourceId(15, R.style.ShapeAppearance_M3_Sys_Shape_Corner_Full) : num3.intValue());
        BadgeState$State badgeState$State10 = this.b;
        Integer num4 = badgeState$State.h;
        badgeState$State10.h = Integer.valueOf(num4 == null ? typedArrayL.getResourceId(16, 0) : num4.intValue());
        BadgeState$State badgeState$State11 = this.b;
        Integer num5 = badgeState$State.b;
        badgeState$State11.b = Integer.valueOf(num5 == null ? AbstractC3442d4.a(context, typedArrayL, 1).getDefaultColor() : num5.intValue());
        BadgeState$State badgeState$State12 = this.b;
        Integer num6 = badgeState$State.d;
        badgeState$State12.d = Integer.valueOf(num6 == null ? typedArrayL.getResourceId(8, R.style.TextAppearance_MaterialComponents_Badge) : num6.intValue());
        Integer num7 = badgeState$State.c;
        if (num7 != null) {
            this.b.c = num7;
        } else if (typedArrayL.hasValue(9)) {
            this.b.c = Integer.valueOf(AbstractC3442d4.a(context, typedArrayL, 9).getDefaultColor());
        } else {
            int iIntValue = this.b.d.intValue();
            TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(iIntValue, com.google.android.material.a.Q);
            typedArrayObtainStyledAttributes.getDimension(0, DefinitionKt.NO_Float_VALUE);
            ColorStateList colorStateListA = AbstractC3442d4.a(context, typedArrayObtainStyledAttributes, 3);
            AbstractC3442d4.a(context, typedArrayObtainStyledAttributes, 4);
            AbstractC3442d4.a(context, typedArrayObtainStyledAttributes, 5);
            typedArrayObtainStyledAttributes.getInt(2, 0);
            typedArrayObtainStyledAttributes.getInt(1, 1);
            int i8 = typedArrayObtainStyledAttributes.hasValue(12) ? 12 : 10;
            typedArrayObtainStyledAttributes.getResourceId(i8, 0);
            typedArrayObtainStyledAttributes.getString(i8);
            typedArrayObtainStyledAttributes.getBoolean(14, false);
            AbstractC3442d4.a(context, typedArrayObtainStyledAttributes, 6);
            typedArrayObtainStyledAttributes.getFloat(7, DefinitionKt.NO_Float_VALUE);
            typedArrayObtainStyledAttributes.getFloat(8, DefinitionKt.NO_Float_VALUE);
            typedArrayObtainStyledAttributes.getFloat(9, DefinitionKt.NO_Float_VALUE);
            typedArrayObtainStyledAttributes.recycle();
            TypedArray typedArrayObtainStyledAttributes2 = context.obtainStyledAttributes(iIntValue, com.google.android.material.a.D);
            typedArrayObtainStyledAttributes2.hasValue(0);
            typedArrayObtainStyledAttributes2.getFloat(0, DefinitionKt.NO_Float_VALUE);
            typedArrayObtainStyledAttributes2.recycle();
            this.b.c = Integer.valueOf(colorStateListA.getDefaultColor());
        }
        BadgeState$State badgeState$State13 = this.b;
        Integer num8 = badgeState$State.s;
        badgeState$State13.s = Integer.valueOf(num8 == null ? typedArrayL.getInt(2, 8388661) : num8.intValue());
        BadgeState$State badgeState$State14 = this.b;
        Integer num9 = badgeState$State.u;
        badgeState$State14.u = Integer.valueOf(num9 == null ? typedArrayL.getDimensionPixelSize(11, resources.getDimensionPixelSize(R.dimen.mtrl_badge_long_text_horizontal_padding)) : num9.intValue());
        BadgeState$State badgeState$State15 = this.b;
        Integer num10 = badgeState$State.v;
        badgeState$State15.v = Integer.valueOf(num10 == null ? typedArrayL.getDimensionPixelSize(10, resources.getDimensionPixelSize(R.dimen.m3_badge_with_text_vertical_padding)) : num10.intValue());
        BadgeState$State badgeState$State16 = this.b;
        Integer num11 = badgeState$State.w;
        badgeState$State16.w = Integer.valueOf(num11 == null ? typedArrayL.getDimensionPixelOffset(18, 0) : num11.intValue());
        BadgeState$State badgeState$State17 = this.b;
        Integer num12 = badgeState$State.x;
        badgeState$State17.x = Integer.valueOf(num12 == null ? typedArrayL.getDimensionPixelOffset(25, 0) : num12.intValue());
        BadgeState$State badgeState$State18 = this.b;
        Integer num13 = badgeState$State.y;
        badgeState$State18.y = Integer.valueOf(num13 == null ? typedArrayL.getDimensionPixelOffset(19, badgeState$State18.w.intValue()) : num13.intValue());
        BadgeState$State badgeState$State19 = this.b;
        Integer num14 = badgeState$State.z;
        badgeState$State19.z = Integer.valueOf(num14 == null ? typedArrayL.getDimensionPixelOffset(26, badgeState$State19.x.intValue()) : num14.intValue());
        BadgeState$State badgeState$State20 = this.b;
        Integer num15 = badgeState$State.C;
        badgeState$State20.C = Integer.valueOf(num15 == null ? typedArrayL.getDimensionPixelOffset(20, 0) : num15.intValue());
        BadgeState$State badgeState$State21 = this.b;
        Integer num16 = badgeState$State.A;
        badgeState$State21.A = Integer.valueOf(num16 == null ? 0 : num16.intValue());
        BadgeState$State badgeState$State22 = this.b;
        Integer num17 = badgeState$State.B;
        badgeState$State22.B = Integer.valueOf(num17 == null ? 0 : num17.intValue());
        BadgeState$State badgeState$State23 = this.b;
        Boolean bool2 = badgeState$State.D;
        badgeState$State23.D = Boolean.valueOf(bool2 == null ? typedArrayL.getBoolean(0, false) : bool2.booleanValue());
        typedArrayL.recycle();
        Locale locale = badgeState$State.n;
        if (locale == null) {
            this.b.n = Locale.getDefault(Locale.Category.FORMAT);
        } else {
            this.b.n = locale;
        }
        this.a = badgeState$State;
    }
}
