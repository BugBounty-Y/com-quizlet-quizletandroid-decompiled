package com.onetrust.otpublishers.headless.UI.Helper;

import android.text.Editable;
import android.text.Html;
import org.xml.sax.XMLReader;

/* loaded from: classes2.dex */
public final class e implements Html.TagHandler {
    public String b;
    public boolean a = true;
    public int c = 1;

    @Override // android.text.Html.TagHandler
    public final void handleTag(boolean z, String str, Editable editable, XMLReader xMLReader) {
        if ("ul".equals(str)) {
            this.b = "UL";
        } else if ("ol".equals(str)) {
            this.b = "OL";
        }
        if ("li".equals(str)) {
            if ("UL".equals(this.b)) {
                if (this.a) {
                    editable.append("\n\t•");
                    this.a = false;
                    return;
                }
            } else if (this.a) {
                editable.append("\n\t").append((CharSequence) String.valueOf(this.c)).append(". ");
                this.a = false;
                this.c++;
                return;
            }
            this.a = true;
        }
    }
}
