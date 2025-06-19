package androidx.emoji2.viewsintegration;

import android.text.Editable;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputConnectionWrapper;
import android.widget.EditText;
import androidx.emoji2.text.j;

/* loaded from: classes.dex */
public final class b extends InputConnectionWrapper {
    public final EditText a;
    public final assistantMode.utils.studiableMetadata.b b;

    public b(EditText editText, InputConnection inputConnection, EditorInfo editorInfo) {
        assistantMode.utils.studiableMetadata.b bVar = new assistantMode.utils.studiableMetadata.b(4);
        super(inputConnection, false);
        this.a = editText;
        this.b = bVar;
        if (j.c()) {
            j.a().h(editorInfo);
        }
    }

    @Override // android.view.inputmethod.InputConnectionWrapper, android.view.inputmethod.InputConnection
    public final boolean deleteSurroundingText(int i, int i2) {
        Editable editableText = this.a.getEditableText();
        this.b.getClass();
        return assistantMode.utils.studiableMetadata.b.K(this, editableText, i, i2, false) || super.deleteSurroundingText(i, i2);
    }

    @Override // android.view.inputmethod.InputConnectionWrapper, android.view.inputmethod.InputConnection
    public final boolean deleteSurroundingTextInCodePoints(int i, int i2) {
        Editable editableText = this.a.getEditableText();
        this.b.getClass();
        return assistantMode.utils.studiableMetadata.b.K(this, editableText, i, i2, true) || super.deleteSurroundingTextInCodePoints(i, i2);
    }
}
