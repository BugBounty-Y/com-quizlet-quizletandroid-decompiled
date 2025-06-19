package com.quizlet.quizletandroid.util;

import android.content.Context;
import android.content.res.Resources;
import com.quizlet.quizletandroid.R;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.LinkedHashMap;
import java.util.Locale;

/* loaded from: classes3.dex */
public class o {
    public final String[] a;
    public final LinkedHashMap b;
    public final SimpleDateFormat c;
    public final Context d;

    public o(Context context) throws Resources.NotFoundException {
        this.d = context.getApplicationContext();
        String[] stringArray = context.getResources().getStringArray(R.array.display_labels_array);
        this.a = stringArray;
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        this.b = linkedHashMap;
        linkedHashMap.put(604800000L, stringArray[2]);
        linkedHashMap.put(54000000L, stringArray[3]);
        linkedHashMap.put(7200000L, stringArray[4]);
        linkedHashMap.put(120000L, stringArray[5]);
        linkedHashMap.put(1L, stringArray[6]);
        linkedHashMap.put(0L, stringArray[7]);
        this.c = new SimpleDateFormat("LLLL yyyy", Locale.getDefault());
    }

    public final long a(long j, long j2) {
        if (j2 == 0) {
            return 0L;
        }
        if (j < j2) {
            return 1L;
        }
        long j3 = j - j2;
        if (j3 <= 1209600000) {
            for (Long l : this.b.keySet()) {
                if (j3 >= l.longValue()) {
                    return l.longValue();
                }
            }
            return 0L;
        }
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(j2);
        int i = calendar.get(1);
        int i2 = calendar.get(2);
        calendar.clear();
        calendar.set(i, i2, 1, 0, 0, 0);
        return calendar.getTimeInMillis();
    }

    public final String b(long j, long j2) {
        LinkedHashMap linkedHashMap = this.b;
        if (linkedHashMap.keySet().contains(Long.valueOf(j2))) {
            return (String) linkedHashMap.get(Long.valueOf(j2));
        }
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(j);
        int i = calendar.get(1);
        int i2 = calendar.get(2);
        calendar.clear();
        calendar.set(i, i2, 1, 0, 0, 0);
        if (j2 == calendar.getTimeInMillis()) {
            return this.a[1];
        }
        calendar.setTimeInMillis(j2);
        return this.d.getString(R.string.in_month_and_year, this.c.format(calendar.getTime()));
    }
}
