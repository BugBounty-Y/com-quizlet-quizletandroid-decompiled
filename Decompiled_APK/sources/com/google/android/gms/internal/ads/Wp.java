package com.google.android.gms.internal.ads;

import android.util.JsonReader;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import java.io.IOException;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class Wp {
    public final int a;
    public final int b;
    public final boolean c;

    public Wp(int i, int i2, boolean z) {
        this.a = i;
        this.b = i2;
        this.c = z;
    }

    public static ArrayList a(JsonReader jsonReader) throws IOException {
        ArrayList arrayList = new ArrayList();
        jsonReader.beginArray();
        while (jsonReader.hasNext()) {
            jsonReader.beginObject();
            int iNextInt = 0;
            int iNextInt2 = 0;
            boolean zNextBoolean = false;
            while (jsonReader.hasNext()) {
                String strNextName = jsonReader.nextName();
                if (OTUXParamsKeys.OT_UX_WIDTH.equals(strNextName)) {
                    iNextInt = jsonReader.nextInt();
                } else if (OTUXParamsKeys.OT_UX_HEIGHT.equals(strNextName)) {
                    iNextInt2 = jsonReader.nextInt();
                } else if ("is_fluid_height".equals(strNextName)) {
                    zNextBoolean = jsonReader.nextBoolean();
                } else {
                    jsonReader.skipValue();
                }
            }
            jsonReader.endObject();
            arrayList.add(new Wp(iNextInt, iNextInt2, zNextBoolean));
        }
        jsonReader.endArray();
        return arrayList;
    }
}
