package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/marki")
public class MarkaController {

    @Autowired
    private MarkaRepository markaRepository;

    @GetMapping
    public List<Marka> getAllMarki() {
        return markaRepository.findAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Marka> getMarkaById(@PathVariable(value = "id") Long id) {
        return markaRepository.findById(id)
                .map(marka -> ResponseEntity.ok().body(marka))
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public Marka createMarka(@RequestBody Marka marka) {
        return markaRepository.save(marka);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Marka> updateMarka(@PathVariable(value = "id") Long id, @RequestBody Marka markaDetails) {
        return markaRepository.findById(id)
                .map(marka -> {
                    marka.setNazwa(markaDetails.getNazwa());
                    Marka updatedMarka = markaRepository.save(marka);
                    return ResponseEntity.ok().body(updatedMarka);
                }).orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteMarka(@PathVariable(value = "id") Long id) {
        return markaRepository.findById(id)
                .map(marka -> {
                    markaRepository.delete(marka);
                    return ResponseEntity.ok().build();
                }).orElse(ResponseEntity.notFound().build());
    }
}