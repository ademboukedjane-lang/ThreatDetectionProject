package threatdetector.service;

import java.util.ArrayList;
import java.util.List;
import threatdetector.model.ScanItem;

public class ParseReport {
    
    public List<ScanItem> items;
    
    public List<String> errors;

    public ParseReport() {
        this.items = new ArrayList<>();
        this.errors = new ArrayList<>();
    }
}