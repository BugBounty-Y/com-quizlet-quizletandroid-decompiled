package com.braze.enums;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.braze.support.BrazeLogger;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class Month {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ Month[] $VALUES;
    public static final Companion Companion;
    private final int value;
    public static final Month JANUARY = new Month("JANUARY", 0, 0);
    public static final Month FEBRUARY = new Month("FEBRUARY", 1, 1);
    public static final Month MARCH = new Month("MARCH", 2, 2);
    public static final Month APRIL = new Month("APRIL", 3, 3);
    public static final Month MAY = new Month("MAY", 4, 4);
    public static final Month JUNE = new Month("JUNE", 5, 5);
    public static final Month JULY = new Month("JULY", 6, 6);
    public static final Month AUGUST = new Month("AUGUST", 7, 7);
    public static final Month SEPTEMBER = new Month("SEPTEMBER", 8, 8);
    public static final Month OCTOBER = new Month("OCTOBER", 9, 9);
    public static final Month NOVEMBER = new Month("NOVEMBER", 10, 10);
    public static final Month DECEMBER = new Month("DECEMBER", 11, 11);

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String getMonth$lambda$2$lambda$1(int i) {
            return AbstractC0147y.c(i, "No month with value ", ", value must be in (0,11)");
        }

        public final Month getMonth(int i) {
            Month month;
            Month[] monthArrValues = Month.values();
            int length = monthArrValues.length;
            int i2 = 0;
            while (true) {
                if (i2 >= length) {
                    month = null;
                    break;
                }
                month = monthArrValues[i2];
                if (month.getValue() == i) {
                    break;
                }
                i2++;
            }
            if (month != null) {
                return month;
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new i(i, 0), 6, (Object) null);
            return null;
        }

        private Companion() {
        }
    }

    private static final /* synthetic */ Month[] $values() {
        return new Month[]{JANUARY, FEBRUARY, MARCH, APRIL, MAY, JUNE, JULY, AUGUST, SEPTEMBER, OCTOBER, NOVEMBER, DECEMBER};
    }

    static {
        Month[] monthArr$values = $values();
        $VALUES = monthArr$values;
        $ENTRIES = AbstractC3328d.f(monthArr$values);
        Companion = new Companion(null);
    }

    private Month(String str, int i, int i2) {
        this.value = i2;
    }

    public static Month valueOf(String str) {
        return (Month) Enum.valueOf(Month.class, str);
    }

    public static Month[] values() {
        return (Month[]) $VALUES.clone();
    }

    public final int getValue() {
        return this.value;
    }
}
