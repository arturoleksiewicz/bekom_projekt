package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/modele")
public class ModelController {

    @Autowired
    private ModelRepository modelRepository;

    @GetMapping
    public List<Model> getAllModele() {
        return modelRepository.findAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Model> getModelById(@PathVariable(value = "id") Long id) {
        return modelRepository.findById(id)
                .map(model -> ResponseEntity.ok().body(model))
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public Model createModel(@RequestBody Model model) {
        return modelRepository.save(model);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Model> updateModel(@PathVariable(value = "id") Long id, @RequestBody Model modelDetails) {
        return modelRepository.findById(id)
                .map(model -> {
                    model.setNazwa(modelDetails.getNazwa());
                    model.setRokProdukcji(modelDetails.getRokProdukcji());
                    model.setMarka(modelDetails.getMarka());
                    Model updatedModel = modelRepository.save(model);
                    return ResponseEntity.ok().body(updatedModel);
                }).orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteModel(@PathVariable(value = "id") Long id) {
        return modelRepository.findById(id)
                .map(model -> {
                    modelRepository.delete(model);
                    return ResponseEntity.ok().build();
                }).orElse(ResponseEntity.notFound().build());
    }
}